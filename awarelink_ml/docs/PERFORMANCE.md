# Local performance measurements

Measured on **1 October 2026** with the real packaged models: URL 1.2.0, SMS 1.0.0 and news 1.0.0. These are observed development-machine measurements, not latency or throughput guarantees. The application has no LLM or remote inference calls. Model stages run inside one process, and SQLite uses persistent per-thread local connections, so those stages have no network handshake.

The final **Uvicorn HTTP/1.1 transport preserved one socket across 221 requests**, including all streamed analyses in the benchmark. There is still an initial client connection, and idle timeouts, proxies or browsers can cause later reconnection. The in-process pipeline removes network exchanges between internal analysis stages; it does not eliminate the initial browser connection or an optional connection to an inspected website.

## Environment and method

- CPython **3.13.5**, Windows 11 **10.0.26300**, AMD64.
- **Intel Core i5-12450HX**, 12 logical CPUs.
- Three direct runtime dependencies: **Uvicorn 0.54.0**, **urllib3 2.8.0**, **Pillow 12.3.0**. Uvicorn adds two small transitive packages: **click 8.5.0** and **h11 0.16.0**. Training libraries are not used by this benchmark.
- Three model artifacts total **1,214,143 bytes** (approximately 1.21 MB).
- **100 timed samples** per inference/input-length combination and per request group, after **10 warm-up calls**. Startup has **10 fresh application initializations**.
- Four analysis workers, queue capacity eight, 16 bounded shared HTTP adapter workers, cache capacity 1,024, benchmark request limit 10,000, SQLite WAL with `synchronous=NORMAL`.
- Median and nearest-rank p95 use wall-clock durations. Runs are sequential; no concurrent throughput claim is made. Background processes and OS scheduling can change timings.

Startup begins after imports and includes a new disposable SQLite database, secret creation, model loading and application initialization. OCR is disabled for this URL/news benchmark. Filesystem caches are not flushed, so this is not a cold interpreter or cold-disk benchmark.

Pure inference uses one loaded registry and fixed short or bounded long inputs. Fresh request measurements use a different raw URL/text for every call, avoiding cache hits. Each request includes session and CSRF checks, the worker pipeline, the entire NDJSON stream, and local persistence. The URL and news request examples are short; the separate long-input inference measurements do not imply long requests have the same overall latency.

## Results

All durations below are **milliseconds**.

| Operation | Input / samples | p50 | p95 |
| --- | --- | ---: | ---: |
| Application initialization | 10 fresh disposable databases | 76.85 | 108.24 |
| URL inference | 33 characters / 100 | 0.069 | 0.164 |
| URL inference | 2,048 characters / 100 | 0.123 | 0.157 |
| SMS inference | 34 characters / 100 | 0.072 | 0.085 |
| SMS inference | 12,000 characters / 100 | 4.04 | 6.43 |
| News inference | 53 characters / 100 | 0.023 | 0.040 |
| News inference | 12,000 characters / 100 | 2.11 | 3.42 |
| Fresh URL, complete WSGI stream and save | 100 unique requests | 0.79 | 1.39 |
| Fresh news, complete WSGI stream and save | 100 unique requests | 0.59 | 0.84 |
| Cached URL, complete WSGI stream and record update | 100 repeated requests | 0.28 | 0.50 |
| Fresh URL over localhost HTTP, stream and save | 100 unique requests | 2.67 | 4.20 |
| Fresh news over localhost HTTP, stream and save | 100 unique requests | 2.53 | 3.21 |
| Fixed-length health request over one persistent socket | 100 requests | 0.81 | 1.05 |

The first measured application initialization was 56.63 ms. The startup p95 is the maximum of ten samples, so it has limited statistical precision. Likewise, short model timings measure individual local calls rather than a service under sustained load.

Localhost HTTP uses an independent Uvicorn server on an ephemeral loopback port, `asyncio`, `h11`, one process and the default five-second keep-alive timeout. The ASGI adapter bridges the existing tested WSGI application through a bounded shared executor and terminates each streamed response explicitly. The benchmark does not use the live preview or its data. Server scheduling, adapter work and response handling account for work excluded by direct WSGI measurements. TLS and remote-network latency are absent.

## Verified reuse and completion

- The registry was constructed **once** for all request benchmarks. Each of the 100 unique URL/news requests in each transport ran **exactly one real model prediction** and saved a unique record.
- Repeating one cached URL **100 times added zero model predictions**, reused the same saved record, and still completed a streamed response and record update.
- **20 duplicate submissions** while one real prediction was pending returned the **same task** and used **one model prediction**. Duplicate submission p50/p95 were **0.0029/0.0077 ms**. A controlled event gate held the first call pending; this verifies the coalescing mechanism, not a natural cache/coalescing rate or end-to-end analysis latency.
- Direct WSGI requests reused **one SQLite connection**. Localhost HTTP used three more adapter-thread connections in this run, producing **four local connections total**. There were **zero database network connections**. The actual connection count depends on which bounded executor threads are used.
- Fresh requests produced four NDJSON events and a saved result. Completion is signaled by the task's future event; these results have no deliberate polling-delay floor.
- Pipeline counters were **562 submitted, 100 cache hits, 20 coalesced, 442 completed and zero failed**. No external fetch was attempted. The disposable database directory and independent HTTP server were removed/stopped after the run.

For final HTTP analysis, **221 total requests** (one bootstrap and 220 warm-up/timed analyses) caused **one socket connect** and one client local endpoint. A separate group of **101 fixed-length health requests also used one socket connect**. The script asserts that analysis streams preserve keep-alive, so a future regression fails the benchmark.

An earlier implementation check found that Waitress 3.0.2 closed unknown-length streamed responses: 221 requests required 220 socket connects, despite reusing the same client object. That finding prompted the transport change. The final measurements above use Uvicorn; the old reconnect behavior was corrected without patching private server internals. The two measurements occurred under ordinary development-machine conditions and are not a controlled comparative throughput study.

## Reproduce

A final repeat in a newly created runtime-only environment (the five packages above, no NumPy/scikit-learn/SciPy/Waitress) passed every benchmark assertion. Its full HTTP p50/p95 were **5.75/7.37 ms URL** and **5.86/6.87 ms news**, and application initialization p50/p95 was **90.72/138.63 ms**. The main preview and ordinary development activity were running concurrently. Both runs verified 221 analysis-flow requests on one connection. This observed variation is a reason to evaluate the actual deployment workload instead of treating a best single run as a guarantee. The original and runtime-only machine-readable reports are [benchmark-reference.json](benchmark-reference.json) and [benchmark-runtime-only.json](benchmark-runtime-only.json).

Install the pinned application runtime dependencies, then run from the project root:

```powershell
python tools/benchmark.py
```

Optional configuration and a machine-readable report:

```powershell
python tools/benchmark.py --samples 100 --warmup 10 --startup-samples 10 --json-output benchmark-report.json
```

The script handles its import path, creates temporary storage, prohibits external website/feed fetching, verifies persistence and reuse, prints all measurements and environment metadata, then closes its workers, server and database. `--skip-http` measures inference and direct WSGI only. The default run completes in seconds on this machine; do not infer a universal runtime bound from that observation.

Screenshot OCR, optional website inspection, news-feed fetching, TLS, browser rendering, cold interpreter launch, hostile inputs, memory saturation and sustained concurrent load are outside this benchmark. Those paths need separate measurements before choosing production capacity or promising service-level targets.
