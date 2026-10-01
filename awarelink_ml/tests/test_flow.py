"""Offline integration tests for reuse, persistence and the analysis flow."""

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from awarelink.config import Settings
from awarelink.storage import Store
from awarelink.pipeline import CapacityError, Pipeline


class FakeModels:
    """Deterministic inference collaborator with optional blocking/failure."""
    def __init__(self, gate=None, failure=None):
        self.calls = []
        self.gate = gate
        self.failure = failure
        self.started = threading.Event()
        self.lock = threading.Lock()

    def predict(self, kind, text):
        with self.lock:
            self.calls.append((kind, text))
        self.started.set()
        if self.gate is not None and not self.gate.wait(timeout=5):
            raise RuntimeError("Test worker was not released.")
        if self.failure:
            raise self.failure
        return {
            "score": 55, "label": "review", "probability": 0.55,
            "model": "offline-test-model", "model_version": "test-v1",
            "signals": ["Test signal"], "limitations": ["Test model"],
            "metrics": {},
        }

    def summary(self):
        return {kind: {"version": "test-v1", "name": "offline-test-model"}
                for kind in ("url", "scam", "news")}


class FakeFetcher:
    def __init__(self):
        self.calls = []

    def inspect(self, url):
        self.calls.append(url)
        return {"reachable": True, "url": url, "status": 200,
                "warnings": [], "redirects": 0}

    def close(self):
        pass


class FakeOCR:
    available = True

    def __init__(self):
        self.calls = []

    @staticmethod
    def validate(data):
        if not data:
            raise ValueError("No test image supplied.")

    def extract(self, data):
        self.calls.append(data)
        return "Urgent: send your verification code to claim a prize."


class StorageFlowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "awarelink.db"
        self.store = Store(self.path)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    @staticmethod
    def payload(fingerprint="one"):
        return {"kind": "news", "fingerprint": fingerprint,
                "private_input": "Sensitive original input.",
                "input_label": "Saved analysis", "score": 55,
                "label": "review", "signals": [], "limitations": []}

    def test_connections_are_reused_per_thread_with_wal_and_foreign_keys(self):
        first = self.store.connection()
        self.assertIs(first, self.store.connection())
        child_connections = []

        def use_connection():
            conn = self.store.connection()
            child_connections.append((conn, self.store.connection()))

        thread = threading.Thread(target=use_connection)
        thread.start()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertIs(child_connections[0][0], child_connections[0][1])
        self.assertIsNot(first, child_connections[0][0])
        for conn in (first, child_connections[0][0]):
            self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertGreaterEqual(conn.execute("PRAGMA busy_timeout").fetchone()[0], 1000)

    def test_same_owner_reuses_record_other_owner_receives_independent_record(self):
        first = self.store.save_analysis("alice", self.payload())
        repeat = self.store.save_analysis("alice", self.payload())
        other = self.store.save_analysis("bob", self.payload())
        self.assertEqual(first["id"], repeat["id"])
        self.assertEqual(first["share_id"], repeat["share_id"])
        self.assertNotEqual(first["id"], other["id"])
        self.assertNotEqual(first["share_id"], other["share_id"])
        self.assertEqual(len(self.store.history("alice")), 1)
        self.assertEqual(len(self.store.history("bob")), 1)
        self.assertNotIn("private_input", first)
        self.assertNotIn("fingerprint", self.store.shared(first["share_id"]))
        self.assertEqual(self.store.overview()["stats"]["total"], 2)

    def test_records_survive_reopening_database(self):
        saved = self.store.save_analysis("alice", self.payload())
        self.store.close()
        self.store = Store(self.path)
        self.assertEqual(self.store.history("alice")[0]["id"], saved["id"])
        self.assertEqual(self.store.shared(saved["share_id"])["id"], saved["id"])

    def test_feedback_enforces_owner_and_cascades_when_analysis_is_deleted(self):
        saved = self.store.save_analysis("alice", self.payload())
        with self.assertRaises(ValueError):
            self.store.add_feedback("bob", saved["id"], True)
        with self.assertRaises(ValueError):
            self.store.add_feedback("alice", "nonexistent", True)
        for invalid in (1, 0, "true", None):
            with self.subTest(accurate=invalid), self.assertRaises(ValueError):
                self.store.add_feedback("alice", saved["id"], invalid)
        feedback = self.store.add_feedback("alice", saved["id"], False, "Wrong assessment")
        self.assertEqual(self.store.overview()["feedback"][0]["id"], feedback["id"])
        self.assertTrue(self.store.delete_analysis(saved["id"]))
        self.assertEqual(self.store.overview()["feedback"], [])
        self.assertIsNone(self.store.shared(saved["share_id"]))

    def test_shared_screenshot_does_not_disclose_extracted_text(self):
        payload = self.payload("screenshot")
        payload.update(kind="screenshot", extracted_text="My private verification code")
        saved = self.store.save_analysis("alice", payload)
        self.assertIn("extracted_text", self.store.history("alice")[0])
        self.assertNotIn("extracted_text", self.store.shared(saved["share_id"]))

    def test_community_exposes_domain_summary_without_owner_paths_queries_or_share_ids(self):
        url = "https://alerts.example.com/private-reset-path?token=secret-query"
        payload = self.payload("community")
        payload.update(kind="url", label="high_risk", score=95,
                       input_label=url, private_input=url,
                       model="offline-test-model", model_version="test-v1",
                       signals=["Private query: secret-query"])
        saved = self.store.save_analysis("private-owner-alice", payload)
        cards = self.store.community()
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0]["input_label"], "alerts.example.com")
        serialized = json.dumps(cards)
        for private in ("private-owner-alice", "private-reset-path", "secret-query", url,
                        saved["id"], saved["share_id"]):
            self.assertNotIn(private, serialized)
        for key in ("owner", "id", "share_id", "private_input", "fingerprint", "extracted_text", "checks"):
            self.assertNotIn(key, cards[0])


class PipelineFlowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def pipeline(self, models=None, **overrides):
        settings = Settings(data_dir=Path(self.directory.name), workers=1,
                            queue_size=1, **overrides)
        self.models = models or FakeModels()
        self.fetcher, self.ocr = FakeFetcher(), FakeOCR()
        pipeline = Pipeline(settings, self.models, fetcher=self.fetcher, ocr=self.ocr)

        def close():
            if self.models.gate:
                self.models.gate.set()
            pipeline.close()

        self.addCleanup(close)
        return pipeline

    def test_duplicate_inflight_inputs_share_one_inference_future(self):
        gate = threading.Event()
        pipeline = self.pipeline(FakeModels(gate=gate))
        first = pipeline.submit("news", "A long enough sample news report for analysis.")
        self.assertTrue(self.models.started.wait(timeout=1))
        duplicate = pipeline.submit("news", "A long enough sample news report for analysis.")
        self.assertIs(first.future, duplicate.future)
        subscriber = duplicate.subscribe()
        self.assertGreater(subscriber.maxsize, 0)
        gate.set()
        self.assertEqual(first.future.result(timeout=2)["kind"], "news")
        self.assertEqual(len(self.models.calls), 1)
        stages = []
        while not subscriber.empty():
            event = subscriber.get_nowait()
            if event["event"] == "stage":
                stages.append(event["stage"])
        self.assertIn("queued", stages)
        self.assertIn("classifying", stages)
        duplicate.unsubscribe(subscriber)

    def test_bounded_queue_rejects_new_work_and_still_accepts_duplicate(self):
        gate = threading.Event()
        pipeline = self.pipeline(FakeModels(gate=gate))
        first = pipeline.submit("news", "First report is long enough to be classified.")
        self.assertTrue(self.models.started.wait(timeout=1))
        second = pipeline.submit("news", "Second report is long enough to be classified.")
        with self.assertRaises(CapacityError):
            pipeline.submit("news", "Third report is long enough to be classified.")
        duplicate = pipeline.submit("news", "First report is long enough to be classified.")
        self.assertIs(first.future, duplicate.future)
        gate.set()
        first.future.result(timeout=2)
        second.future.result(timeout=2)
        third = pipeline.submit("news", "Third report is long enough to be classified.")
        third.future.result(timeout=2)
        self.assertEqual(len(self.models.calls), 3)

    def test_recent_results_are_cached_with_copy_isolation_and_bounded_eviction(self):
        pipeline = self.pipeline(cache_size=2)
        text = "This is the first sufficiently long news sample."
        first = pipeline.submit("news", text)
        original = first.future.result(timeout=2)
        original["signals"].append("A caller's local modification")
        cached = pipeline.submit("news", text)
        self.assertTrue(cached.cached)
        self.assertNotIn("A caller's local modification", cached.future.result(timeout=2)["signals"])
        self.assertEqual(len(self.models.calls), 1)
        for index in (2, 3):
            pipeline.submit("news", f"This is sufficiently long news sample number {index}.").future.result(timeout=2)
        evicted = pipeline.submit("news", text)
        self.assertFalse(evicted.cached)
        evicted.future.result(timeout=2)
        self.assertEqual(len(self.models.calls), 4)

    def test_expired_cache_and_failed_inference_are_not_reused(self):
        pipeline = self.pipeline(cache_ttl=0)
        text = "This sufficiently long news report has no reusable cache."
        pipeline.submit("news", text).future.result(timeout=2)
        second = pipeline.submit("news", text)
        self.assertFalse(second.cached)
        second.future.result(timeout=2)
        self.assertEqual(len(self.models.calls), 2)
        self.models.failure = RuntimeError("Model unavailable")
        failed_text = "This sufficiently long news report fails during inference."
        with self.assertRaisesRegex(RuntimeError, "Model unavailable"):
            pipeline.submit("news", failed_text).future.result(timeout=2)
        self.models.failure = None
        recovered = pipeline.submit("news", failed_text)
        self.assertFalse(recovered.cached)
        recovered.future.result(timeout=2)
        self.assertEqual(len(self.models.calls), 4)

    def test_offline_url_scan_uses_no_fetch_and_inspection_is_a_distinct_cache_key(self):
        pipeline = self.pipeline()
        url = "https://example.com/login"
        pipeline.submit("url", url).future.result(timeout=2)
        self.assertEqual(self.fetcher.calls, [])
        self.assertTrue(pipeline.submit("url", url).cached)
        inspected = pipeline.submit("url", url, inspect=True)
        self.assertFalse(inspected.cached)
        result = inspected.future.result(timeout=2)
        self.assertEqual(self.fetcher.calls, [url])
        self.assertIn("checks", result)

    def test_screenshot_runs_local_ocr_then_scam_model_without_fetching_urls(self):
        pipeline = self.pipeline()
        result = pipeline.submit("screenshot", b"offline-test-image").future.result(timeout=2)
        self.assertEqual(self.ocr.calls, [b"offline-test-image"])
        self.assertEqual(self.models.calls[0][0], "scam")
        self.assertEqual(result["kind"], "screenshot")
        self.assertIn("extracted_text", result)
        self.assertEqual(self.fetcher.calls, [])

    def threshold_sensitive_prediction(self, kind, text):
        result = FakeModels.predict(self.models, kind, text)
        if kind == "scam":
            result.update(score=45, probability=0.45, label="high_risk")
        else:
            result.update(score=70, probability=0.70, label="review")
        result.update(model=f"{kind}-test-model", metrics={"source": kind},
                      limitations=[f"{kind} model limitations"])
        return result

    def test_screenshot_merge_preserves_high_risk_despite_higher_review_score(self):
        pipeline = self.pipeline()
        text = "Suspicious message links to https://example.com/ and http://127.0.0.1/private."
        with patch.object(self.ocr, "extract", return_value=text), patch.object(
                self.models, "predict", side_effect=self.threshold_sensitive_prediction):
            result = pipeline.submit("screenshot", b"offline-test-image").future.result(timeout=2)
        self.assertEqual(result["label"], "high_risk")
        self.assertEqual(result["score"], 70)
        self.assertEqual(result["metrics"], {"source": "url"})
        self.assertEqual([component["label"] for component in result["components"]], ["high_risk", "review"])
        self.assertIn("scam model limitations", result["limitations"])
        self.assertIn("url model limitations", result["limitations"])
        self.assertTrue(any("local address" in signal for signal in result["signals"]))
        self.assertEqual(self.fetcher.calls, [])

    def test_inspected_page_high_risk_is_preserved_across_different_model_thresholds(self):
        pipeline = self.pipeline()
        checks = {"url": "https://example.com/", "status": 200,
                  "page_text": "A sufficiently long suspicious website message.", "password_fields": 0}
        with patch.object(self.fetcher, "inspect", return_value=checks), patch.object(
                self.models, "predict", side_effect=self.threshold_sensitive_prediction):
            result = pipeline.submit("url", "https://example.com/", inspect=True).future.result(timeout=2)
        self.assertEqual(result["label"], "high_risk")
        self.assertEqual(result["score"], 70)
        self.assertEqual(result["checks"]["text_label"], "high_risk")


class ApplicationFlowTests(unittest.TestCase):
    def setUp(self):
        from awarelink.app import create_app
        from test_security import response_cookie, wsgi_request

        self.request_wsgi, self.cookie_from = wsgi_request, response_cookie
        self.directory = tempfile.TemporaryDirectory()
        self.models, self.fetcher, self.ocr = FakeModels(), FakeFetcher(), FakeOCR()
        self.settings = Settings(data_dir=Path(self.directory.name), secret="s" * 48,
                                 workers=1, queue_size=1, request_limit=1000)
        self.app = create_app(self.settings, models=self.models,
                              fetcher=self.fetcher, ocr=self.ocr)
        self.cookie, self.csrf = self.bootstrap()

    def tearDown(self):
        if self.models.gate:
            self.models.gate.set()
        self.app.close()
        self.directory.cleanup()

    def bootstrap(self):
        response = self.request_wsgi(self.app)
        self.assertEqual(response["status"], 200)
        return self.cookie_from(response), response["json"]["csrf_token"]

    def analyze(self, text, cookie=None, csrf=None, **kwargs):
        return self.request_wsgi(self.app, "POST", "/api/analyze",
            data={"kind": "news", "input": text},
            cookie=self.cookie if cookie is None else cookie,
            headers={"X-CSRF-Token": self.csrf if csrf is None else csrf}, **kwargs)

    @staticmethod
    def events(response):
        return [json.loads(line) for line in response["body"].splitlines() if line.strip()]

    def result(self, response):
        self.assertEqual(response["status"], 200)
        events = self.events(response)
        results = [event["result"] for event in events if event["event"] == "result"]
        self.assertEqual(len(results), 1)
        self.assertFalse(any(event["event"] == "error" for event in events))
        return results[0]

    def test_one_ndjson_request_emits_stages_and_a_saved_result(self):
        response = self.analyze("A news report with enough text for the local model.")
        headers = {key.lower(): value for key, value in response["headers"]}
        self.assertIn("application/x-ndjson", headers["content-type"])
        result = self.result(response)
        stages = {event["stage"] for event in self.events(response) if event["event"] == "stage"}
        self.assertTrue({"queued", "classifying", "saving"}.issubset(stages))
        self.assertIn("id", result)
        self.assertIn("share_id", result)
        self.assertNotIn("fingerprint", result)
        self.assertNotIn("private_input", result)
        self.assertEqual(self.app.storage.overview()["stats"]["total"], 1)
        self.assertEqual(len(self.models.calls), 1)

    def test_first_stream_chunk_arrives_while_inference_is_still_running(self):
        gate = threading.Event()
        self.models.gate = gate
        response = self.analyze("A sample news report that blocks during model inference.", stream=True)
        try:
            first = json.loads(next(response["iterator"]))
            self.assertEqual(first["event"], "stage")
            self.assertTrue(self.models.started.wait(timeout=1))
            self.assertFalse(gate.is_set())
            gate.set()
            remaining = [json.loads(chunk) for chunk in response["iterator"] if chunk.strip()]
            self.assertEqual(sum(event["event"] == "result" for event in remaining), 1)
        finally:
            gate.set()
            response["close"]()

    def test_shared_inference_creates_separate_owner_records_and_history(self):
        text = "A shared sample report classified locally for two browser sessions."
        first = self.result(self.analyze(text))
        second_cookie, second_csrf = self.bootstrap()
        second = self.result(self.analyze(text, cookie=second_cookie, csrf=second_csrf))
        self.assertEqual(len(self.models.calls), 1)
        self.assertTrue(second["cached"])
        self.assertNotEqual(first["id"], second["id"])
        self.assertNotEqual(first["share_id"], second["share_id"])
        for cookie, record in ((self.cookie, first), (second_cookie, second)):
            response = self.request_wsgi(self.app, path="/api/history", cookie=cookie)
            self.assertEqual(response["status"], 200)
            self.assertEqual([item["id"] for item in response["json"]["history"]], [record["id"]])
        shared = self.request_wsgi(self.app, path=f"/api/analyses/{first['share_id']}")
        self.assertEqual(shared["status"], 200)
        self.assertEqual(shared["json"]["result"]["id"], first["id"])

    def test_feedback_uses_saved_id_and_rejects_another_sessions_record(self):
        result = self.result(self.analyze("A sample report with feedback tied to a stable saved record."))
        other_cookie, other_csrf = self.bootstrap()
        denied = self.request_wsgi(self.app, "POST", "/api/feedback",
            data={"analysis_id": result["id"], "accurate": False}, cookie=other_cookie,
            headers={"X-CSRF-Token": other_csrf})
        self.assertIn(denied["status"], (400, 403, 404))
        self.assertEqual(self.app.storage.overview()["feedback"], [])
        accepted = self.request_wsgi(self.app, "POST", "/api/feedback",
            data={"analysis_id": result["id"], "accurate": False, "reason": "Wrong result"},
            cookie=self.cookie, headers={"X-CSRF-Token": self.csrf})
        self.assertIn(accepted["status"], (200, 201))
        self.assertEqual(self.app.storage.overview()["feedback"][0]["analysis_id"], result["id"])

    def test_model_and_persistence_failures_emit_error_without_successful_save(self):
        self.models.failure = RuntimeError("sensitive-internal-detail")
        with self.assertLogs("awarelink.app", level="ERROR"):
            failed = self.analyze("A valid sample that fails during local model inference.")
        events = self.events(failed)
        self.assertEqual(sum(event["event"] == "error" for event in events), 1)
        self.assertFalse(any(event["event"] == "result" for event in events))
        self.assertNotIn(b"sensitive-internal-detail", failed["body"])
        self.assertEqual(self.app.storage.overview()["stats"]["total"], 0)
        self.models.failure = None
        with patch.object(self.app.storage, "save_analysis", side_effect=RuntimeError("disk failure")), self.assertLogs("awarelink.app", level="ERROR"):
            failed_save = self.analyze("Another valid sample fails while its result is being saved.")
        events = self.events(failed_save)
        self.assertEqual(sum(event["event"] == "error" for event in events), 1)
        self.assertFalse(any(event["event"] == "result" for event in events))
        self.assertEqual(self.app.storage.overview()["stats"]["total"], 0)

    def test_malformed_model_output_is_rejected_before_persistence(self):
        malformed = (
            {"score": 101}, {"score": True}, {"probability": float("nan")},
            {"probability": float("inf")}, {"probability": 1.5},
            {"probability": "0.55"}, {"label": "unknown"}, {"signals": "not a list"},
        )
        for index, changes in enumerate(malformed):
            prediction = {
                "score": 55, "label": "review", "probability": 0.55,
                "model": "offline-test-model", "model_version": "test-v1",
                "signals": [], "limitations": [], "metrics": {},
            }
            prediction.update(changes)
            with self.subTest(changes=changes), patch.object(self.models, "predict", return_value=prediction):
                response = self.analyze(f"Malformed prediction case {index} is a sufficiently long sample.")
                events = self.events(response)
                self.assertEqual(sum(event["event"] == "error" for event in events), 1)
                self.assertFalse(any(event["event"] == "result" for event in events))
                self.assertEqual(self.app.storage.overview()["stats"]["total"], 0)

    def test_queue_saturation_returns_explicit_http_error_without_saving(self):
        gate = threading.Event()
        self.models.gate = gate
        first = self.app.pipeline.submit("news", "First report is occupying the single analysis worker.")
        self.assertTrue(self.models.started.wait(timeout=1))
        second = self.app.pipeline.submit("news", "Second report is occupying the single queued work slot.")
        try:
            response = self.analyze("Third report must be rejected until there is queue capacity.")
            self.assertIn(response["status"], (429, 503))
            self.assertIsNotNone(response["json"]["error"])
            self.assertEqual(self.app.storage.overview()["stats"]["total"], 0)
        finally:
            gate.set()
            first.future.result(timeout=2)
            second.future.result(timeout=2)


if __name__ == "__main__":
    unittest.main()
