"""Verify packaged model behavior using only the Python standard library.

Run with `python -S training/verify_models.py` to exclude third-party packages.
The fitting script additionally checks sklearn/export parity on held-out data.
"""

import json
from pathlib import Path
import statistics
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from awarelink.ml import MAX_TEXT_LENGTH, MAX_URL_LENGTH, ModelRegistry


class PackagedModels(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = ModelRegistry(ROOT / "models")
        cls.report = json.loads((ROOT / "training" / "evaluation.json").read_text(encoding="utf-8"))

    def test_export_agrees_with_held_out_trained_predictions(self):
        for model in self.registry.summary().values():
            self.assertLess(model["training"]["export_parity_max_probability_error"], 1e-6)
            self.assertGreater(model["evaluation"]["test"]["samples"], 500)

    def test_representative_examples_match_export_check(self):
        for kind, examples in self.report["illustrative_samples_not_evaluation"].items():
            for example in examples:
                result = self.registry.predict(kind, example["input"])
                self.assertAlmostEqual(result["probability"], example["result"]["probability"], places=6)
                self.assertGreaterEqual(result["score"], 0)
                self.assertLessEqual(result["score"], 100)
                self.assertTrue(result["limitations"])

    def test_news_always_requires_review(self):
        for text in ("The moon is made of cheese.", "A parliamentary committee released its report.", "The city has a population of one million."):
            self.assertEqual(self.registry.predict("news", text)["label"], "review")

    def test_absent_english_features_require_review(self):
        self.assertEqual(self.registry.predict("scam", "你好世界！")["label"], "review")

    def test_missing_model_fails_explicitly(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                ModelRegistry(Path(directory))

    def test_invalid_inputs_are_bounded(self):
        for kind, text in (("scam", "x" * (MAX_TEXT_LENGTH + 1)), ("url", "x" * (MAX_URL_LENGTH + 1)), ("news", " "), ("unknown", "test")):
            with self.assertRaises(ValueError):
                self.registry.predict(kind, text)

    def test_summary_cannot_mutate_loaded_thresholds(self):
        summary = self.registry.summary()
        original = summary["url"]["thresholds"]["high"]
        summary["url"]["thresholds"]["high"] = 0
        self.assertEqual(self.registry.summary()["url"]["thresholds"]["high"], original)

    def test_ordinary_deep_links_are_not_automatically_high_risk(self):
        for url in ("https://docs.python.org/3/library/urllib.parse.html", "https://en.wikipedia.org/wiki/Machine_learning", "https://github.com/05RANDOM-pmustudent/SESSION-1-25-26-FYP"):
            self.assertNotEqual(self.registry.predict("url", url)["label"], "high_risk")

    def test_domain_score_invariant_to_subdomain_scheme_and_path(self):
        scores = [self.registry.predict("url", url)["probability"] for url in ("https://www.python.org/", "http://docs.python.org/3/library/urllib.parse.html?query=123")]
        self.assertEqual(scores[0], scores[1])


def benchmark():
    registry = ModelRegistry(ROOT / "models")
    samples = {
        "url": "https://example.org/" + "verify-123/" * 200,
        "scam": ("Please review this message and its source. " * 400)[:MAX_TEXT_LENGTH],
        "news": ("The statement requires independent source verification. " * 300)[:MAX_TEXT_LENGTH],
    }
    samples["url"] = samples["url"][:MAX_URL_LENGTH]
    result = {}
    for kind, sample in samples.items():
        elapsed = []
        for _ in range(100):
            start = time.perf_counter()
            registry.predict(kind, sample)
            elapsed.append((time.perf_counter() - start) * 1000)
        elapsed.sort()
        result[kind] = {"input_characters": len(sample), "p50_ms": round(statistics.median(elapsed), 3), "p95_ms": round(elapsed[94], 3)}
    print("Bounded long-input inference, 100 warm runs, no network or queue: " + json.dumps(result))


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PackagedModels)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.wasSuccessful():
        benchmark()
    sys.exit(not result.wasSuccessful())
