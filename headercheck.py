#!/usr/bin/env python3
"""headercheck - audits HTTP security headers for a site and grades them.
Standard library only; works against any URL you are authorized to test."""
import argparse, json, ssl, sys, urllib.request, urllib.error

CHECKS = {
 "strict-transport-security": ("A", "F", "HSTS: forces HTTPS and blocks downgrade attacks. Add 'max-age=63072000; includeSubDomains; preload'."),
 "content-security-policy": ("A", "F", "CSP: main defense against XSS and data injection. Start with a restrictive default-src."),
 "x-content-type-options": ("A", "D", "Set 'nosniff' so browsers never MIME-sniff responses."),
 "x-frame-options": ("A", "C", "Set DENY or SAMEORIGIN (or use CSP frame-ancestors) to stop clickjacking."),
 "referrer-policy": ("A", "C", "Control referrer leakage; 'strict-origin-when-cross-origin' is a solid default."),
 "permissions-policy": ("B", "C", "Restrict camera, mic, geolocation and other powerful features."),
 "cross-origin-opener-policy": ("B", "C", "Isolate your browsing context (e.g. 'same-origin')."),
 "cross-origin-resource-policy": ("B", "C", "Control which origins may embed your resources."),
}
LEAKY = ["server", "x-powered-by", "x-aspnet-version", "x-generator", "x-drupal-cache"]
GRADE_POINTS = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}

def fetch_headers(url, timeout):
    req = urllib.request.Request(url, method="GET",
        headers={"User-Agent": "headercheck/1.0 (+https://example.com/headercheck)"})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, url

def audit(url, timeout):
    status, hdrs, final_url = fetch_headers(url, timeout)
    results, points, possible = [], 0, 0
    for name, (present, missing, advice) in CHECKS.items():
        ok = name in hdrs
        grade = present if ok else missing
        if name == "x-content-type-options" and ok and hdrs[name].strip().lower() != "nosniff":
            grade, advice = "C", "Present but should be exactly 'nosniff'."
        points += GRADE_POINTS[grade]; possible += 4
        results.append({"header": name, "present": ok, "grade": grade,
                        "value": hdrs.get(name), "advice": advice})
    leaks = [{"header": n, "value": hdrs[n]} for n in LEAKY if n in hdrs]
    pct = points / possible if possible else 0
    overall = ("A+" if pct >= .95 and not leaks else "A" if pct >= .85 else
               "B" if pct >= .7 else "C" if pct >= .5 else "D" if pct >= .3 else "F")
    return {"url": url, "final_url": final_url, "status": status, "grade": overall,
            "score_pct": round(pct * 100), "checks": results, "info_leaks": leaks}

def main():
    ap = argparse.ArgumentParser(description="Audit HTTP security headers and grade a site.")
    ap.add_argument("urls", nargs="+", help="One or more URLs to check.")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("-o", "--output", help="Write JSON report to this file.")
    ap.add_argument("-q", "--quiet", action="store_true", help="Only print the grade line per URL.")
    args = ap.parse_args()
    reports, worst = [], "A+"
    order = ["A+", "A", "B", "C", "D", "F"]
    for url in args.urls:
        try:
            r = audit(url, args.timeout)
        except Exception as e:
            print(f"[!] {url}: {e}"); continue
        reports.append(r)
        print(f"\n{r['url']}  ->  HTTP {r['status']}  grade {r['grade']} ({r['score_pct']}%)")
        if order.index(r["grade"]) > order.index(worst): worst = r["grade"]
        if not args.quiet:
            for c in r["checks"]:
                mark = "ok" if c["present"] else "MISSING"
                print(f"  [{c['grade']}] {c['header']:<34} {mark}")
                if not c["present"]: print(f"       {c['advice']}")
            for l in r["info_leaks"]:
                print(f"  [leak] {l['header']}: {l['value']}  (consider removing)")
    if args.output:
        with open(args.output, "w") as f: json.dump(reports, f, indent=2)
        print(f"\n[*] JSON written to {args.output}")
    sys.exit(0 if worst in ("A+", "A", "B") else 1)

if __name__ == "__main__":
    main()
