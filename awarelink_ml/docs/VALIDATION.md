# Validation

Validated on 1 October 2026 with CPython 3.13.5 on Windows 11. The complete automated suite passed **62 tests, with no failures or skipped tests**, in 5.482 seconds. Tests use disposable databases and controlled inputs; they do not write to the original project or a remote service.

Run the suite from the project directory:

```powershell
python -m unittest discover -s tests -v
```

## What the tests verify

| Area | Verified behavior |
|---|---|
| Destination safety | Reject private, local, link-local, reserved, multicast, mapped IPv6 and IPv6 transition addresses; reject mixed public/private DNS answers, credentials in URLs, invalid schemes/ports and control characters. |
| Website inspection | Pin the connection to a checked public address while preserving the original Host and TLS identity; validate redirected destinations; reject HTTPS downgrades; limit redirects, declared/actual body sizes and compressed responses; reuse a host's DNS entry and connection pool. |
| Overall network deadline | Real `http.client.HTTPResponse` parsing over a controlled socket stops continuously dripping HTTP headers and buffered response bodies using a 100 ms total budget. Progress inside an inactivity timeout cannot keep the tested operations alive indefinitely. |
| Administration and sessions | Protect every implemented admin read/delete route; require session CSRF tokens for mutations; reject cross-site Origin/Fetch Metadata; rotate login sessions, revoke logout sessions, reject tampered/expired cookies, and preserve valid sessions across restart with the persisted secret. |
| Input and OCR bounds | Reject malformed/incomplete JSON, unsupported request types and oversized text, URLs, request bodies and uploads before inference. Reject excessive multipart fields before MIME parsing. Validate actual image formats/dimensions, including a forged oversized PNG header. Verify OCR timeout, argument-list execution and its one-thread setting. |
| Shared processing | Bound running/queued inference; coalesce identical in-flight work; reuse recent results with TTL/LRU limits and copy isolation; keep inspection mode separate in cache keys; retry after model failure. Default URL scans and screenshot extraction perform no website fetches. |
| Decisions and persistence | Preserve a high-risk label when another classifier has a higher numeric score but a weaker label. Reject malformed/non-finite predictions before saving. Model or database exceptions produce a terminal error without a successful result or saved row. |
| Ownership and privacy | Reuse a record within one owner's history while giving another owner an independent record. Require feedback ownership and a saved analysis ID; cascade feedback deletion through a foreign key. Shared screenshot results omit extracted text. Community summaries omit owner IDs, paths, query secrets and share IDs. |
| Database reuse | Reuse one SQLite connection per thread; enable WAL, foreign keys and a busy timeout; retain records after reopening the database. Unknown non-API paths create no persistent sessions. |
| HTTP transport | Forward Cookie, CSRF, Origin, body and query data into WSGI; preserve repeated Set-Cookie headers; emit incremental NDJSON in one response with a final `more_body=False`; reject excess transport work before executor submission; propagate disconnect cancellation, close the stream and release admission; close shared resources on lifespan shutdown. |

The test files are [test_security.py](../tests/test_security.py), [test_flow.py](../tests/test_flow.py), and [test_transport.py](../tests/test_transport.py).

The complete suite also passed in a fresh runtime-only environment with exactly Uvicorn, urllib3, Pillow, click and h11, with no training libraries installed: **62/62**, no skips, 8.617 seconds. `pip check` found no broken requirements. Separately, `python -S training/verify_models.py` passed **9/9** packaged-model checks with third-party site packages disabled. These verify exported predictions, input bounds, mandatory news review, domain/path invariance and detached model metadata; they do not demonstrate live detection accuracy.

## Browser checks

The real localhost interface was exercised with URL and news analyses, streamed progress, history, feedback, share links and a real Tesseract screenshot containing a controlled sample message. OCR completed and its text/policy signal appeared; shared output omitted the extracted-text field. A new check on a shared-result page completed with the correct session/CSRF initialization. At 320 px and 390 px widths, the tested main screen had no horizontal overflow. Browser warnings and errors were absent in the checked flows.

An isolated administrator preview verified login, overview, kind filtering, feedback empty state, all three model cards and logout. A final main-preview reload verified content-versioned asset URLs and that an unconfigured administrator sees the setup notice with the credential form hidden. Asset versions are calculated from the preloaded CSS/JS bytes at startup, avoiding stale assets after a release. These are browser smoke checks, not an exhaustive accessibility or cross-browser certification.

## Independent benchmark check

The real-model benchmark also completed successfully with 100 measured samples per flow, 10 warm-up calls and 10 startup samples:

```powershell
python tools/benchmark.py --samples 100 --warmup 10 --startup-samples 10 --json-output benchmark-results.json
```

The rerun verified **221 localhost HTTP requests over one client socket**, including complete analysis streams. It loaded the model registry once for the request benchmark, saved every successful result, reused cached results without additional inference, and coalesced 20 duplicate submissions made while one controlled prediction remained in flight. The benchmark attempted zero external fetches and removed its disposable database afterward. See [PERFORMANCE.md](PERFORMANCE.md) for measurements and their scope.

## Limits of this validation

Control-flow tests use deterministic model collaborators; passing them does not establish classifier accuracy. The benchmark uses the exported models, but measures execution and persistence rather than detection quality. Dataset evaluation and model limitations are documented in [MODEL_CARD.md](MODEL_CARD.md); news classification does not verify the truth of a claim.

The automated network tests use controlled resolvers, pools and sockets. They verify rejection, pinning and deadline behavior without contacting internal addresses or malicious sites. They are not a full penetration test or proof against every operating-system/TLS edge case.

The OCR subprocess test substitutes a timeout failure. It checks process bounds and image validation, rather than measuring Tesseract accuracy or screenshot authenticity. The localhost benchmark excludes external website latency, OCR, public TLS, reverse proxies and sustained production traffic; its results are not an internet latency or capacity guarantee.
