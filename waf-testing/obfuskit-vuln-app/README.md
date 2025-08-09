A vulnerable app filled with encoding and normalization problems.
ObfuskitVulnApp – intentionally vulnerable normalization playground

Run locally:

```
go run ./waf-testing/obfuskit-vuln-app
```

Docker:

```
docker build -t obfuskitvulnapp -f waf-testing/obfuskit-vuln-app/Dockerfile .
docker run --rm -p 8881:8881 obfuskitvulnapp
```

Endpoints (examples):

- echo: `GET /echo?q=%253Cscript%253Ealert(1)%253C%2Fscript%253E&enc=url,url&mode=raw`
- decode: `GET /decode?mode=b64&value=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==&repeat=1`
- normalize: `GET /normalize?u=..%2f..%2fetc%2fpasswd`
- path: `GET /path?file=..%2f..%2fREADME.md`
- pathwin: `GET /pathwin?file=..\\..\\README.md`
- json: `POST /json` with `Content-Type: text/plain` and body `a=1&b=2&a=3` then also `?a=9` in URL
- mime: `POST /mime` with multipart file containing HTML to see sniffing/rendering
- upload: `POST /upload` multipart with filename like `..\\..\\evil.txt` (saves under tmp/uploads)
- filter: `GET /filter?q=%253Cscript%253Ealert(1)%253C%2Fscript%253E` (double URL-encoded to bypass)
- xss: `GET /xss?q=%26%23x73%3Bcript%3Ealert(1)%3C%2Fscript%3E` (bypass with hex entity)
- headers: `GET /headers?pick=last&key=X-Test` with repeated headers `X-Test: one` and `X-Test: two`
- cookies: `GET /cookies?name=SESSION&pick=last` with repeated `Cookie: SESSION=a; SESSION=b`
- nullbyte: `GET /nullbyte?name=admin%00;drop`
- hpp: `GET /hpp?a=1&a=2&a=3`
- semicolon: `GET /semicolon?raw=a=1;b=2&also=c` (treats `;` like `&`)
- methods: `POST /methods` + header `X-HTTP-Method-Override: TRACE`
- chain: `GET /chain?value=...&steps=url,b64,hex`
- proxy: `GET /proxy` with `X-Forwarded-For: 127.0.0.1`
- desync: `GET /desync` (behavior varies; intended for proxy testing)
- case: `GET /case?Param=AAA&param=bbb&pArAm=ccc`
- xml: `POST /xml` with a `<!ENTITY name SYSTEM "file:///etc/hosts">` and `&name;` in body

Client UI
- Open `http://localhost:8881/ui/` for an intentionally unsafe client that renders responses as HTML. Useful to exercise XSS endpoints like `/xss` and `/echo?mode=raw`.

Security note: This app is intentionally unsafe. Do not expose it to the internet.