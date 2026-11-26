# headercheck

Audits the HTTP security headers of any site you are authorized to test and grades them A+ to F, with concrete fix advice for every gap.

## Features
- Checks HSTS, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP and CORP
- Flags information-leak headers (`Server`, `X-Powered-By`, framework version headers)
- Grade per header and overall percentage score; value validation (e.g. nosniff must be exact)
- Audit many URLs in one run; JSON report for tracking posture over time
- Exit code 0 only when the worst grade is B or better - drop it into CI

## Usage
```
python3 headercheck.py https://example.com
python3 headercheck.py https://app.example.com https://api.example.com -o posture.json
```

## Sample output
```
https://example.com  ->  HTTP 200  grade D (34%)
  [F] strict-transport-security          MISSING
       HSTS: forces HTTPS and blocks downgrade attacks. Add 'max-age=63072000; includeSubDomains; preload'.
  [leak] server: ECS (nyb/1D18)  (consider removing)
```

## License
MIT
