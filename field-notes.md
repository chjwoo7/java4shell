# Field notes — validating the primitive

Generic observations, no host/customer/network identifiers.

## Lab (same image as the deployment under test)

| Item | Value |
|---|---|
| Product | Keycloak 26.8.1 (official image build) |
| JDK | OpenJDK 21.0.13+9-LTS (Red Hat) |
| JVM flags | `UseAVX=3`, `UseBASE64Intrinsics=true`, G1GC |
| Host CPU | `avx512f avx512bw avx512vbmi bmi2` |

Results on the lab runtime:

- `Base64Trigger` → `REPRODUCED` (`changed=62 first=50 last=111`).
- After ~20k valid HTTP Basic decodes, `jcmd <pid> Compiler.perfmap` listed
  C2-compiled `java.util.Base64$Decoder.decodeBlock` / `decode0` frames.
- The primitive is real on this runtime and lands deterministically:
  a `byte[65]` decode destination followed by a `byte[64]` array gives a
  fixed `88`-byte distance, and the spill overwrites the neighbour's mark
  word, klass pointer and length (`0x699aa669`).
- `lab/research/Chain4.java` extends the corrupted length into a 4096-byte
  reader and discloses a planted heap string (`RESULT=DISCLOSURE_OK`).

> The earlier claim in this file that the full chain reached `RESULT=RCE_OK`
> was wrong. That Java program set a boolean on its own object and then called
> `ProcessBuilder` from its own `main`; `lab/research/NoBugControl.java`
> reproduces the same output with the vulnerability removed. A real remote
> chain is `java4shell.py` against `lab/spring`.

## Trigger is one-shot

After the decode throws `IllegalArgumentException`, `decode0`/`decodeBlock`
go *"made not entrant"* (`-XX:+PrintCompilation`) and are deoptimized. Each
landing therefore needs a fresh warm window (~20k valid decodes):

```
phase1 (no re-warm):  attempt 0 landed, attempts 1-19 did not   -> 1/20
phase2 (re-warm 50k):                                          -> 7/8
```

## Remote deployment (redacted)

| Check | Result |
|---|---|
| Keycloak | 26.8.1 |
| JDK | OpenJDK 21.0.13+9-LTS — unpatched (fix: 21.0.13.1) |
| Pre-auth path | token endpoint decodes the malformed Basic header (`401 invalid_client`) |
| Warm + trigger | 20k warm, 200×65-byte + 200×129-byte triggers, all normal responses |
| Crash / restart | none |
| CPU flags | **`bmi2` only** — no `avx512f` / `avx512bw` / `avx512vbmi` |

Conclusion: the JDK is vulnerable but the host cannot execute the vulnerable
intrinsic, so the trigger is a no-op. This is a **hardware-gated** bug; the
same image becomes exploitable if scheduled onto an AVX-512 VBMI node.

## Lessons

1. JDK version alone is not a verdict. Confirm the four CPU flags on the host
   actually running the JVM.
2. A benign remote run proves only delivery (the header reached a Base64
   decode), never safety.
3. A CDN in front of the service is not a boundary: the origin was reachable
   directly by IP with the right SNI/Host, and the WAF only enforced a
   browser-like User-Agent.
4. Placement matters: on mixed-node clusters, a non-VBMI node today can become
   a vulnerable one after rescheduling. Upgrade the JDK and/or set
   `-XX:-UseBASE64Intrinsics` regardless.
5. A one-shot trigger breaks loop-based drivers: warm → one trigger →
   re-warm. Firing hundreds of triggers after a single warm lands at most once.
6. Do not trust a boolean your own exploit code sets and then acts on. That is
   not code execution, and it survives deleting the vulnerability entirely.
