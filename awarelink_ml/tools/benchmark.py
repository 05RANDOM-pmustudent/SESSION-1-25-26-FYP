"""Measure real local inference and request flows against a disposable database.

Run: python tools/benchmark.py
Optional: --samples 100 --warmup 10 --startup-samples 10 --json-output report.json
No external sites, feeds, API keys, production data or preview server are used.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from http.client import HTTPConnection
from http.cookies import SimpleCookie
import importlib.metadata
import io
import json
import math
import os
from pathlib import Path
import platform
import socket
import statistics
import sys
import tempfile
import threading
import time
from unittest.mock import patch
from wsgiref.util import setup_testing_defaults

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from awarelink.app import create_app
from awarelink.config import Settings
from awarelink.ml import MAX_TEXT_LENGTH, MAX_URL_LENGTH, ModelRegistry
import uvicorn


def distribution(values):
    ordered = sorted(values)
    return {
        "samples": len(values), "p50_ms": round(statistics.median(values), 4),
        "p95_ms": round(ordered[max(0, math.ceil(.95 * len(values)) - 1)], 4),
        "min_ms": round(ordered[0], 4), "max_ms": round(ordered[-1], 4),
    }


class NoNetwork:
    def __init__(self):
        self.attempts = 0

    def fetch(self, *args, **kwargs):
        self.attempts += 1
        raise AssertionError("External fetching is prohibited during this benchmark")

    inspect = fetch

    def close(self):
        pass


class NoOCR:
    available = False


class ObservedRegistry(ModelRegistry):
    loads = 0

    def __init__(self, models_dir):
        type(self).loads += 1
        super().__init__(models_dir)
        self.calls = Counter()
        self.lock = threading.Lock()
        self.gate = None

    def predict(self, kind, text):
        with self.lock:
            self.calls[kind] += 1
            gate, self.gate = self.gate, None
        if gate is not None:
            entered, release = gate
            entered.set()
            if not release.wait(5):
                raise RuntimeError("Benchmark coalescing gate timed out")
        return super().predict(kind, text)


def settings(data_dir):
    return Settings(base_dir=ROOT, data_dir=data_dir, host="127.0.0.1", port=0,
                    request_limit=10000, cache_size=1024, workers=4, queue_size=8)


def result_event(body):
    events = [json.loads(line) for line in body.splitlines() if line]
    errors = [event for event in events if event.get("event") == "error"]
    results = [event["result"] for event in events if event.get("event") == "result"]
    if errors or len(results) != 1:
        raise AssertionError(f"Unexpected analysis stream: errors={errors}, results={len(results)}")
    result = results[0]
    if not result.get("id") or not result.get("share_id"):
        raise AssertionError("Stream finished without a persisted analysis")
    return result, len(events)


class WSGIClient:
    def __init__(self, app):
        self.app, self.cookie, self.csrf = app, "", ""

    def call(self, path, method="GET", data=None):
        body = json.dumps(data, separators=(",", ":")).encode() if data is not None else b""
        environ = {}
        setup_testing_defaults(environ)
        environ.update(REQUEST_METHOD=method, PATH_INFO=path, HTTP_HOST="localhost",
                       REMOTE_ADDR="127.0.0.1", CONTENT_TYPE="application/json",
                       CONTENT_LENGTH=str(len(body)), HTTP_COOKIE=self.cookie,
                       HTTP_X_CSRF_TOKEN=self.csrf, **{"wsgi.input": io.BytesIO(body)})
        response = {}

        def start_response(status, headers, exc_info=None):
            response.update(status=int(status.split()[0]), headers=headers)

        started = time.perf_counter()
        iterable = self.app(environ, start_response)
        try:
            output = b"".join(iterable)
        finally:
            if hasattr(iterable, "close"):
                iterable.close()
        elapsed = (time.perf_counter() - started) * 1000
        for name, value in response["headers"]:
            if name.lower() == "set-cookie":
                cookies = SimpleCookie(value)
                self.cookie = "; ".join(f"{key}={item.value}" for key, item in cookies.items())
        if response["status"] != 200:
            raise AssertionError(f"HTTP {response['status']}: {output[:500]!r}")
        return output, elapsed

    def bootstrap(self):
        body, _ = self.call("/api/bootstrap")
        self.csrf = json.loads(body)["csrf_token"]

    def analyze(self, kind, text):
        body, elapsed = self.call("/api/analyze", "POST", {"kind": kind, "input": text, "inspect": False})
        result, event_count = result_event(body)
        return result, elapsed, event_count


class ObservedHTTPConnection(HTTPConnection):
    connects = 0

    def connect(self):
        self.connects += 1
        super().connect()


class HTTPClient:
    def __init__(self, port):
        self.connection = ObservedHTTPConnection("127.0.0.1", port, timeout=10)
        self.cookie, self.csrf = "", ""
        self.socket_ids = set()

    def call(self, path, method="GET", data=None):
        body = json.dumps(data, separators=(",", ":")).encode() if data is not None else None
        headers = {"Content-Type": "application/json", "Cookie": self.cookie, "X-CSRF-Token": self.csrf}
        started = time.perf_counter()
        self.connection.request(method, path, body, headers)
        self.socket_ids.add(self.connection.sock.getsockname())
        response = self.connection.getresponse()
        output = response.read()
        elapsed = (time.perf_counter() - started) * 1000
        if response.status != 200:
            raise AssertionError(f"HTTP {response.status}: {output[:500]!r}")
        if cookie := response.getheader("Set-Cookie"):
            cookies = SimpleCookie(cookie)
            self.cookie = "; ".join(f"{key}={item.value}" for key, item in cookies.items())
        return output, elapsed

    def bootstrap(self):
        body, _ = self.call("/api/bootstrap")
        self.csrf = json.loads(body)["csrf_token"]

    def analyze(self, kind, text):
        body, elapsed = self.call("/api/analyze", "POST", {"kind": kind, "input": text, "inspect": False})
        result, event_count = result_event(body)
        return result, elapsed, event_count


def unique_input(kind, prefix, index):
    if kind == "url":
        return f"https://sample-{prefix}-{index}.example/benchmark/{index}?run={prefix}"
    return f"The city council approved a new bus service in benchmark district {prefix}, statement number {index}. Verify the original source."


def timed_requests(client, app, samples, warmup, prefix):
    output = {}
    for kind in ("url", "news"):
        for index in range(warmup):
            client.analyze(kind, unique_input(kind, prefix + "warmup", index))
        before = app.models.calls[kind]
        values, ids, stages = [], set(), []
        for index in range(samples):
            result, elapsed, event_count = client.analyze(kind, unique_input(kind, prefix, index))
            assert not result["cached"], "Fresh input unexpectedly reused cache"
            values.append(elapsed)
            ids.add(result["id"])
            stages.append(event_count)
        assert len(ids) == samples, "Unique inputs did not persist unique records"
        assert app.models.calls[kind] - before == samples, "Fresh analysis did not run exactly once"
        output[kind] = {**distribution(values), "warmup_requests": warmup,
                        "persisted_unique_records": len(ids), "real_model_calls": app.models.calls[kind] - before,
                        "stream_events_min": min(stages), "stream_events_max": max(stages)}
    return output


def cpu_name():
    if os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                return winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
        except OSError:
            pass
    return platform.processor() or "unavailable"


def benchmark(args):
    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {"python": sys.version.split()[0], "implementation": platform.python_implementation(),
                        "platform": platform.platform(), "machine": platform.machine(), "cpu": cpu_name(),
                        "logical_cpu_count": os.cpu_count(), "runtime_dependencies": {
                            name: importlib.metadata.version(name) for name in ("uvicorn", "urllib3", "Pillow")},
                        "transitive_transport_dependencies": {name: importlib.metadata.version(name) for name in ("click", "h11")}},
        "parameters": {"samples": args.samples, "warmup": args.warmup, "startup_samples": args.startup_samples,
                       "workers": 4, "queue_size": 8, "request_limit": 10000, "sqlite": "WAL, synchronous=NORMAL",
                       "percentile": "nearest rank p95", "inference_inputs": "fixed bounded short/long; requests use unique text/URLs"},
        "model_bytes": {path.name: path.stat().st_size for path in (ROOT / "models").glob("*.json")},
        "scope": "Sequential local microbenchmarks; no screenshots/OCR, website inspection, external feed, TLS, browser rendering or concurrent throughput test",
    }
    model_sizes = report["model_bytes"]
    report["model_bytes_total"] = sum(model_sizes.values())
    registry = ModelRegistry(ROOT / "models")
    report["model_versions"] = {kind: model["version"] for kind, model in registry.summary().items()}
    samples = {
        "url": {"short": "https://www.python.org/downloads/", "long": ("https://long-domain-38271.example/" + "verify-123/" * 300)[:MAX_URL_LENGTH]},
        "scam": {"short": "Can we meet at the library at six?", "long": ("Please review this message and independently verify the sender. " * 300)[:MAX_TEXT_LENGTH]},
        "news": {"short": "The city council approved a new bus route on Tuesday.", "long": ("The statement requires independent source verification and careful review. " * 300)[:MAX_TEXT_LENGTH]},
    }
    report["pure_inference"] = {}
    for kind, lengths in samples.items():
        report["pure_inference"][kind] = {}
        for length, text in lengths.items():
            for _ in range(args.warmup):
                registry.predict(kind, text)
            elapsed = []
            for _ in range(args.samples):
                started = time.perf_counter()
                registry.predict(kind, text)
                elapsed.append((time.perf_counter() - started) * 1000)
            report["pure_inference"][kind][length] = {**distribution(elapsed), "characters": len(text), "warmup": args.warmup}

    with tempfile.TemporaryDirectory(prefix="awarelink-benchmark-") as directory:
        directory = Path(directory)
        starts = []
        for index in range(args.startup_samples):
            no_network = NoNetwork()
            started = time.perf_counter()
            app = create_app(settings(directory / f"startup-{index}"), fetcher=no_network, ocr=NoOCR())
            starts.append((time.perf_counter() - started) * 1000)
            app.close()
            assert no_network.attempts == 0
        report["application_startup"] = {**distribution(starts), "first_initialization_ms": round(starts[0], 4),
                                        "scope": "After module imports, fresh disposable DB and secret, models loaded from disk, local OCR disabled; OS file cache not flushed"}
        network = NoNetwork()
        with patch("awarelink.ml.ModelRegistry", ObservedRegistry):
            before_loads = ObservedRegistry.loads
            app = create_app(settings(directory / "requests"), fetcher=network, ocr=NoOCR())
            try:
                client = WSGIClient(app)
                client.bootstrap()
                connection_identity = id(app.storage.connection())
                report["full_wsgi_stream_and_persistence"] = timed_requests(client, app, args.samples, args.warmup, "wsgi")
                assert id(app.storage.connection()) == connection_identity
                report["sqlite_reuse"] = {"same_thread_connection_reused": True,
                                           "connections_after_wsgi": len(app.storage._connections), "database_network_connections": 0}

                repeated = "https://cache-sample.example/repeated-local-analysis"
                initial, _, _ = client.analyze("url", repeated)
                before = app.models.calls["url"]
                elapsed, ids = [], set()
                for _ in range(args.samples):
                    result, duration, _ = client.analyze("url", repeated)
                    assert result["cached"]
                    elapsed.append(duration)
                    ids.add(result["id"])
                assert ids == {initial["id"]}
                assert app.models.calls["url"] == before
                report["cache_reuse_full_wsgi"] = {**distribution(elapsed), "additional_model_calls": 0,
                                                  "persisted_record_reused": True, "includes": "session, NDJSON stream, existing SQLite record update"}

                entered, release = threading.Event(), threading.Event()
                app.models.gate = (entered, release)
                before = app.models.calls["news"]
                coalesced_before = app.pipeline.metrics["coalesced"]
                task = app.pipeline.submit("news", unique_input("news", "coalescing", 0))
                try:
                    assert entered.wait(5), "Real model call did not reach the controlled pending gate"
                    elapsed, identities = [], []
                    for _ in range(20):
                        started = time.perf_counter()
                        duplicate = app.pipeline.submit("news", unique_input("news", "coalescing", 0))
                        elapsed.append((time.perf_counter() - started) * 1000)
                        identities.append(duplicate is task)
                finally:
                    release.set()
                task.future.result(timeout=5)
                assert all(identities)
                assert app.models.calls["news"] - before == 1
                assert app.pipeline.metrics["coalesced"] - coalesced_before == 20
                report["shared_inflight"] = {"duplicate_submissions": 20, "identical_task_returned": True,
                                             "real_model_calls": 1, "duplicate_submission_latency": distribution(elapsed),
                                             "method": "A controlled event gate holds one real prediction pending; this verifies coalescing, not natural hit rate or analysis latency"}

                if not args.skip_http:
                    from awarelink.transport import ASGIAdapter
                    adapter = ASGIAdapter(app)
                    report["parameters"]["http_adapter_workers"] = adapter.workers
                    server = uvicorn.Server(uvicorn.Config(adapter, host="127.0.0.1", port=0,
                        loop="asyncio", http="h11", lifespan="off", access_log=False, log_level="warning"))
                    listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    listening_socket.bind(("127.0.0.1", 0))
                    port = listening_socket.getsockname()[1]
                    server_thread = threading.Thread(target=server.run, kwargs={"sockets": [listening_socket]},
                                                     name="benchmark-http", daemon=True)
                    server_thread.start()
                    deadline = time.monotonic() + 5
                    while not server.started:
                        if not server_thread.is_alive() or time.monotonic() >= deadline:
                            server.should_exit = True
                            raise AssertionError("Disposable HTTP server did not start")
                        threading.Event().wait(.005)
                    http = HTTPClient(port)
                    try:
                        http.bootstrap()
                        report["localhost_http_stream_and_persistence"] = timed_requests(http, app, args.samples, args.warmup, "http")
                        assert http.connection.connects == 1, "Analysis streams did not preserve HTTP keep-alive"
                        assert len(http.socket_ids) == 1
                        report["http_analysis_transport"] = {"client_connect_calls": http.connection.connects,
                                                     "distinct_client_local_endpoints": len(http.socket_ids),
                                                     "total_http_requests": 1 + 2 * (args.samples + args.warmup),
                                                     "one_socket_reused_across_all_requests": http.connection.connects == 1,
                                                     "protocol": "HTTP/1.1, loopback without TLS",
                                                     "server": "Uvicorn, h11, asyncio, one process, ephemeral port, default 5-second keep-alive",
                                                     "note": "One client socket is verified across bootstrap, warm-up and timed analysis streams"}
                        fixed = HTTPClient(port)
                        try:
                            fixed.call("/health")
                            elapsed = [fixed.call("/health")[1] for _ in range(args.samples)]
                            assert fixed.connection.connects == 1
                            assert len(fixed.socket_ids) == 1
                            report["http_keep_alive_fixed_length_health"] = {**distribution(elapsed),
                                "client_connect_calls": fixed.connection.connects,
                                "distinct_client_local_endpoints": len(fixed.socket_ids),
                                "requests_on_one_socket": args.samples + 1,
                                "includes": "Health route only; no model prediction, session or persistence"}
                        finally:
                            fixed.connection.close()
                        report["sqlite_reuse"]["connections_after_http"] = len(app.storage._connections)
                        assert len(app.storage._connections) <= adapter.workers + 1, "Database connections exceeded one caller plus bounded request workers"
                    finally:
                        http.connection.close()
                        server.should_exit = True
                        server_thread.join(timeout=3)
                        listening_socket.close()
                        if hasattr(adapter, "close"):
                            adapter.close()
                        if server_thread.is_alive():
                            raise AssertionError("Disposable HTTP server did not stop")

                assert network.attempts == 0
                assert ObservedRegistry.loads - before_loads == 1
                report["checks"] = {"real_models": True, "registry_loads_for_request_benchmarks": 1,
                                    "external_fetch_attempts": 0, "no_llm_or_remote_inference": True,
                                    "full_stream_results_persisted": True, "cache_avoids_inference": True,
                                    "duplicate_inflight_uses_one_inference": True,
                                    "pipeline_metrics": dict(app.pipeline.metrics)}
            finally:
                app.close()
    assert not directory.exists(), "Disposable benchmark database directory remains"
    report["checks"]["temp_database_removed_on_exit"] = True
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--startup-samples", type=int, default=10)
    parser.add_argument("--skip-http", action="store_true")
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    if not 10 <= args.samples <= 1000 or not 0 <= args.warmup <= 100 or not 1 <= args.startup_samples <= 100:
        parser.error("Use samples 10–1000, warmup 0–100, startup-samples 1–100")
    report = benchmark(args)
    serialized = json.dumps(report, indent=2)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(serialized + "\n", encoding="utf-8")
    print(serialized)


if __name__ == "__main__":
    main()
