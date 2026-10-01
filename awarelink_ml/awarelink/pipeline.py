"""In-process work queue, shared inference, TTL cache and streamed stages."""
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
import copy
import hashlib
import json
import logging
import math
import queue
import re
import threading
import time

from .network import normalize_url

log = logging.getLogger(__name__)


class CapacityError(RuntimeError):
    pass


class Task:
    def __init__(self, future=None, cached=False, coalesced=False):
        self.future = future or Future()
        self.cached = cached
        self.coalesced = coalesced
        self._stages = []
        self._subscribers = set()
        self._lock = threading.Lock()
        self.future.add_done_callback(self._notify_done)

    def _notify_done(self, future):
        event = {"event": "_done", "stage": "complete"}
        with self._lock:
            self._stages.append(event)
            for subscriber in self._subscribers:
                try:
                    subscriber.put_nowait(event)
                except queue.Full:
                    pass

    def emit(self, stage, message):
        event = {"event": "stage", "stage": stage, "message": message}
        with self._lock:
            self._stages.append(event)
            for subscriber in self._subscribers:
                try:
                    subscriber.put_nowait(event)
                except queue.Full:
                    pass

    def subscribe(self):
        events = queue.Queue(maxsize=16)
        with self._lock:
            for stage in self._stages:
                events.put_nowait(stage)
            self._subscribers.add(events)
        return events

    def unsubscribe(self, subscriber):
        with self._lock:
            self._subscribers.discard(subscriber)


class Pipeline:
    def __init__(self, settings, models, store=None, fetcher=None, ocr=None):
        self.settings, self.models = settings, models
        self.fetcher, self.ocr = fetcher, ocr
        self._executor = ThreadPoolExecutor(max_workers=settings.workers, thread_name_prefix="analysis")
        self._capacity = threading.BoundedSemaphore(settings.workers + settings.queue_size)
        self._cache, self._inflight = OrderedDict(), {}
        self._lock = threading.Lock()
        self._closed = False
        self.model_signature = hashlib.sha256(json.dumps(models.summary(), sort_keys=True).encode()).hexdigest()
        self.metrics = {"submitted": 0, "cache_hits": 0, "coalesced": 0, "completed": 0, "failed": 0}

    def submit(self, kind, input_data, inspect=False, filename=""):
        if self._closed:
            raise RuntimeError("Pipeline is closed.")
        if kind not in ("url", "news", "screenshot"):
            raise ValueError("Unknown analysis type.")
        if kind == "url":
            input_data = normalize_url(input_data, self.settings.max_url_chars)
        elif kind == "news":
            if not isinstance(input_data, str) or not 20 <= len(input_data.strip()) <= self.settings.max_text_chars:
                raise ValueError(f"Paste between 20 and {self.settings.max_text_chars} characters.")
            input_data = input_data.strip()
        else:
            if not isinstance(input_data, bytes) or not input_data or len(input_data) > self.settings.max_image_bytes:
                raise ValueError("Screenshot exceeds the upload limit.")
            if not self.ocr or not self.ocr.available:
                raise ValueError("Local OCR is not available.")
            self.ocr.validate(input_data)
        if type(inspect) is not bool or (inspect and kind != "url"):
            raise ValueError("Website inspection is only available for URLs.")
        content = input_data if isinstance(input_data, bytes) else input_data.encode("utf-8")
        fingerprint = hashlib.sha256(kind.encode() + bytes([inspect]) + self.model_signature.encode() + content).hexdigest()
        with self._lock:
            self.metrics["submitted"] += 1
            cached = self._cache.get(fingerprint)
            if cached and cached[0] > time.monotonic():
                self._cache.move_to_end(fingerprint)
                self.metrics["cache_hits"] += 1
                task = Task(cached=True)
                task.emit("classifying", "Reusing a recent local result.")
                task.future.set_result(copy.deepcopy(cached[1]))
                return task
            if fingerprint in self._inflight:
                self.metrics["coalesced"] += 1
                return self._inflight[fingerprint]
            if not self._capacity.acquire(blocking=False):
                raise CapacityError("The analysis queue is full. Please try again shortly.")
            task = Task()
            task.emit("queued", "Your analysis is ready for local processing.")
            self._inflight[fingerprint] = task
            try:
                self._executor.submit(self._run, task, fingerprint, kind, input_data, inspect)
            except Exception:
                self._inflight.pop(fingerprint, None)
                self._capacity.release()
                raise
            return task

    def _run(self, task, fingerprint, kind, input_data, inspect):
        started = time.perf_counter()
        try:
            if kind == "screenshot":
                task.emit("extracting", "Reading screenshot text on this computer.")
                text = self.ocr.extract(input_data)[:self.settings.max_text_chars]
                task.emit("classifying", "Checking the extracted text with a trained local model.")
                result = self.models.predict("scam", text)
                result["components"] = [{key: copy.deepcopy(result[key]) for key in ("score", "label", "model", "model_version", "metrics")}]
                result["extracted_text"] = text
                result["input_label"] = "Screenshot · text analysis"
                result["private_input"] = text
                result["limitations"] = list(result.get("limitations", [])) + ["Screenshot analysis reads text; it does not verify logos, identities or image authenticity."]
                self._credential_policy(result, text)
                for matched in re.findall(r"https?://[^\s<>\"']+", text)[:5]:
                    try:
                        candidate = normalize_url(matched.rstrip(".,);"))
                        url_result = self.models.predict("url", candidate)
                        result["components"].append({key: copy.deepcopy(url_result[key]) for key in ("score", "label", "model", "model_version", "metrics")})
                        result["signals"].append(f"Extracted URL: {candidate}")
                        result["limitations"] = list(dict.fromkeys(result["limitations"] + url_result["limitations"]))
                        severity = {"low_risk": 0, "review": 1, "high_risk": 2}
                        result["label"] = max((result["label"], url_result["label"]), key=lambda label: severity[label])
                        if url_result["score"] > result["score"]:
                            result["score"] = url_result["score"]
                            result["probability"] = url_result["probability"]
                            result["metrics"] = copy.deepcopy(url_result["metrics"])
                            result["model"] += " + " + url_result["model"]
                            result["model_version"] += " + " + url_result["model_version"]
                    except ValueError:
                        result["signals"].append("An extracted URL was malformed or targeted a local address.")
                        if result["label"] == "low_risk":
                            result["label"] = "review"
            elif kind == "url":
                task.emit("classifying", "Assessing URL patterns with the local phishing classifier.")
                result = self.models.predict("url", input_data)
                result.update(input_label=input_data, private_input=input_data)
                if inspect:
                    task.emit("inspecting", "Inspecting the public website through a reusable connection.")
                    try:
                        checks = self.fetcher.inspect(input_data)
                        page_text = checks.pop("page_text", "")
                        if len(page_text) >= 20:
                            page_result = self.models.predict("scam", page_text[:self.settings.max_text_chars])
                            self._credential_policy(page_result, page_text)
                            checks["text_score"] = page_result["score"]
                            checks["text_label"] = page_result["label"]
                            result["signals"].extend(page_result["signals"][:3])
                            result["components"] = [{key: copy.deepcopy(prediction[key]) for key in ("score", "label", "model", "model_version", "metrics")}
                                                    for prediction in (result, page_result)]
                            severity = {"low_risk": 0, "review": 1, "high_risk": 2}
                            result["label"] = max((result["label"], page_result["label"]), key=lambda label: severity[label])
                            if page_result["score"] > result["score"]:
                                result.update(score=page_result["score"], probability=page_result["probability"], metrics=copy.deepcopy(page_result["metrics"]))
                            result["model"] += " + " + page_result["model"]
                            result["model_version"] += " + " + page_result["model_version"]
                            result["limitations"] = list(dict.fromkeys(result["limitations"] + page_result["limitations"]))
                            result["limitations"].append("Website text is assessed with a historical message-spam model; this is an additional language signal.")
                        result["checks"] = checks
                        if checks.get("password_fields"):
                            result["signals"].append("This page contains a password field. Verify the domain before entering credentials.")
                    except Exception as error:
                        log.info("Website inspection unavailable: %s", type(error).__name__)
                        result["checks"] = {"available": False, "message": "The website could not be inspected within the secure limits."}
                        result["limitations"].append("Live inspection was unavailable; the displayed score uses URL patterns only.")
            else:
                task.emit("classifying", "Assessing language patterns with the local research model.")
                result = self.models.predict("news", input_data)
                result.update(input_label=f"News text · {len(input_data):,} characters", private_input=input_data)
            self._validate_prediction(result)
            result.update(kind=kind, fingerprint=fingerprint, cached=False,
                          elapsed_ms=round((time.perf_counter() - started) * 1000, 2))
            with self._lock:
                self._cache[fingerprint] = (time.monotonic() + self.settings.cache_ttl, copy.deepcopy(result))
                self._cache.move_to_end(fingerprint)
                while len(self._cache) > self.settings.cache_size:
                    self._cache.popitem(last=False)
                self._inflight.pop(fingerprint, None)
                self.metrics["completed"] += 1
            task.future.set_result(result)
        except Exception as error:
            with self._lock:
                self._inflight.pop(fingerprint, None)
                self.metrics["failed"] += 1
            task.future.set_exception(error)
        finally:
            self._capacity.release()

    @staticmethod
    def _credential_policy(result, text):
        # This transparent policy preserves a known blind spot in the SMS-trained model.
        if re.search(r"\b(?:send|share|provide|give|reply|enter)\b.{0,80}\b(?:password|passcode|otp|one.time code|pin)\b", text, re.I | re.S):
            signal = "Credential request detected: independently verify the sender. This is a review rule, separate from the ML score."
            if signal not in result["signals"]:
                result["signals"].append(signal)
            if result["label"] == "low_risk":
                result["label"] = "review"

    @staticmethod
    def _validate_prediction(result):
        if not isinstance(result, dict) or type(result.get("score")) is not int or not 0 <= result["score"] <= 100:
            raise ValueError("Model returned an invalid score.")
        if result.get("label") not in ("low_risk", "review", "high_risk"):
            raise ValueError("Model returned an invalid label.")
        probability = result.get("probability")
        if type(probability) not in (int, float) or not math.isfinite(probability) or not 0 <= probability <= 1:
            raise ValueError("Model returned an invalid probability.")
        if not all(isinstance(result.get(key), str) and result[key] for key in ("model", "model_version")):
            raise ValueError("Model returned an invalid identity.")
        if not all(isinstance(result.get(key), list) and all(isinstance(item, str) for item in result[key]) for key in ("signals", "limitations")):
            raise ValueError("Model returned an invalid explanation.")
        json.dumps(result, allow_nan=False)

    def close(self):
        self._closed = True
        self._executor.shutdown(wait=True, cancel_futures=False)
