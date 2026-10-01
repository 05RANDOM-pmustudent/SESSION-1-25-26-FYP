"""Small WSGI application: no web framework, template engine or client bundle."""
from collections import OrderedDict, deque
from email.parser import BytesParser
from email.policy import default
from http import HTTPStatus
from pathlib import Path
from urllib.parse import urlsplit
import copy
import hashlib
import io
import json
import logging
import queue
import re
import threading
import time
import xml.etree.ElementTree as ET

from .auth import Auth
from .config import Settings
from .network import SafeFetcher
from .ocr import LocalOCR
from .pipeline import Pipeline, CapacityError
from .storage import Store

log = logging.getLogger(__name__)


class HTTPError(Exception):
    def __init__(self, status, code, message):
        self.status, self.code, self.message = status, code, message


class Application:
    def __init__(self, settings=None, models=None, fetcher=None, ocr=None):
        self.settings = settings or Settings.from_env()
        self.storage = Store(self.settings.data_dir / "awarelink.sqlite3")
        self.auth = Auth(self.settings, self.storage)
        if models is None:
            from .ml import ModelRegistry
            models = ModelRegistry(self.settings.base_dir / "models")
        self.models = models
        self.fetcher = fetcher or SafeFetcher()
        self.ocr = ocr or LocalOCR(self.settings.ocr_command)
        self.pipeline = Pipeline(self.settings, models, self.storage, self.fetcher, self.ocr)
        self._rate_lock = threading.Lock()
        self._rates = OrderedDict()
        self._news_lock = threading.Lock()
        self._news_cache = (0, [])
        self._static = {}
        for name, mime in (("index.html", "text/html"), ("app.css", "text/css"), ("app.js", "application/javascript")):
            path = self.settings.base_dir / "static" / name
            if path.is_file():
                self._static["/" if name == "index.html" else "/" + name] = (path.read_bytes(), mime + "; charset=utf-8")
        if "/" in self._static:
            html, mime = self._static["/"]
            for asset in ("app.css", "app.js"):
                if "/" + asset in self._static:
                    version = hashlib.sha256(self._static["/" + asset][0]).hexdigest()[:12].encode("ascii")
                    pattern = rb"/" + re.escape(asset.encode("ascii")) + rb"(?:\?v=[a-zA-Z0-9]+)?"
                    html = re.sub(pattern, b"/" + asset.encode("ascii") + b"?v=" + version, html)
            self._static["/"] = (html, mime)

    @staticmethod
    def _security_headers():
        return [
            ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
            ("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        ]

    def _response(self, start_response, status, data, cookie=None, headers=None):
        body = json.dumps(data, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        response_headers = [("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(body))), ("Cache-Control", "no-store")]
        response_headers += self._security_headers()
        if self.settings.secure_cookie:
            response_headers.append(("Strict-Transport-Security", "max-age=31536000"))
        if cookie:
            response_headers.append(("Set-Cookie", cookie))
        response_headers += headers or []
        start_response(f"{status} {HTTPStatus(status).phrase}", response_headers)
        return [body]

    def _check_rate(self, environ, path):
        if not path.startswith("/api/"):
            return
        key = (environ.get("REMOTE_ADDR", "unknown"), "login" if path == "/api/login" else "api")
        now = time.monotonic()
        limit = min(self.settings.request_limit, 10) if key[1] == "login" else self.settings.request_limit
        window = 60 if key[1] == "login" else self.settings.request_window
        with self._rate_lock:
            events = self._rates.setdefault(key, deque())
            self._rates.move_to_end(key)
            while events and events[0] <= now - window:
                events.popleft()
            if len(events) >= limit:
                raise HTTPError(429, "rate_limit", "Too many requests. Please wait a moment.")
            events.append(now)
            while len(self._rates) > 4096:
                self._rates.popitem(last=False)

    def _read_body(self, environ):
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError as error:
            raise HTTPError(400, "invalid_length", "Invalid request length.") from error
        if length < 0 or length > self.settings.max_body_bytes:
            raise HTTPError(413, "body_too_large", "The request is larger than the upload limit.")
        if length == 0:
            raise HTTPError(400, "empty_body", "The request body is empty.")
        body = environ["wsgi.input"].read(length)
        if len(body) != length:
            raise HTTPError(400, "incomplete_body", "The request body is incomplete.")
        return body

    def _json_body(self, environ):
        if environ.get("CONTENT_TYPE", "").split(";", 1)[0].strip().lower() != "application/json":
            raise HTTPError(415, "content_type", "Send a JSON request.")
        try:
            result = json.loads(self._read_body(environ).decode("utf-8"))
        except (ValueError, UnicodeError) as error:
            raise HTTPError(400, "invalid_json", "The JSON request is malformed.") from error
        if not isinstance(result, dict):
            raise HTTPError(400, "invalid_json", "Send a JSON object.")
        return result

    def _analyze_body(self, environ):
        content_type = environ.get("CONTENT_TYPE", "")
        if content_type.lower().startswith("multipart/form-data;"):
            body = self._read_body(environ)
            try:
                boundary_match = re.search(r'(?:^|;)\s*boundary=(?:"([^"\r\n]+)"|([^;\s]+))', content_type, re.I)
                boundary = next((value for value in boundary_match.groups() if value), "") if boundary_match else ""
                if len(content_type) > 256 or not re.fullmatch(r"[A-Za-z0-9'()+_,./:=?-]{1,70}", boundary):
                    raise ValueError("Invalid upload boundary.")
                delimiter = b"--" + boundary.encode("ascii")
                if not body.startswith(delimiter + b"\r\n") or not body.rstrip(b"\r\n").endswith(delimiter + b"--"):
                    raise ValueError("Incomplete multipart upload.")
                if body.count(b"\r\n" + delimiter) > 4:
                    raise ValueError("Too many upload fields.")
                message = BytesParser(policy=default).parsebytes(b"Content-Type: " + content_type.encode("ascii") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body)
                if not message.is_multipart():
                    raise ValueError("Invalid multipart request.")
                parts = list(message.iter_parts())
                if len(parts) > 4:
                    raise ValueError("Too many upload fields.")
                fields = {}
                for part in parts:
                    name = part.get_param("name", header="content-disposition")
                    if not name or name in fields or part.is_multipart():
                        raise ValueError("Invalid or repeated upload field.")
                    fields[name] = part.get_payload(decode=True) or b""
                kind = fields.get("kind", b"screenshot").decode("ascii")
                image = fields.get("file", fields.get("screenshot", b""))
                if kind != "screenshot" or not image:
                    raise ValueError("Select a screenshot file.")
                if len(image) > self.settings.max_image_bytes:
                    raise HTTPError(413, "image_too_large", "Use a screenshot smaller than 2 MB.")
                if not self.ocr.available:
                    raise HTTPError(503, "ocr_unavailable", "Install local Tesseract with English language data to analyze screenshots.")
                return kind, image, False
            except HTTPError:
                raise
            except (ValueError, UnicodeError) as error:
                raise HTTPError(400, "invalid_upload", str(error)) from error
        data = self._json_body(environ)
        kind = data.get("kind")
        value = data.get("input")
        inspect = data.get("inspect", False)
        if kind not in ("url", "news") or not isinstance(value, str):
            raise HTTPError(400, "invalid_input", "Select URL or news analysis and provide text.")
        if type(inspect) is not bool:
            raise HTTPError(400, "invalid_input", "Website inspection must be true or false.")
        return kind, value.strip(), inspect

    def _check_csrf(self, environ, session):
        token = environ.get("HTTP_X_CSRF_TOKEN", "")
        if not self.auth.csrf_valid(session, token):
            raise HTTPError(403, "csrf", "Refresh the page before submitting this request.")
        if environ.get("HTTP_SEC_FETCH_SITE") == "cross-site":
            raise HTTPError(403, "origin", "Cross-site requests are not accepted.")
        origin = environ.get("HTTP_ORIGIN")
        expected = environ.get("wsgi.url_scheme", "http") + "://" + environ.get("HTTP_HOST", "")
        if origin and origin != expected:
            raise HTTPError(403, "origin", "Cross-site requests are not accepted.")

    def _stream(self, task, session, start_response, cookie, started, cancelled=None):
        headers = [("Content-Type", "application/x-ndjson; charset=utf-8"), ("Cache-Control", "no-store"), ("X-Accel-Buffering", "no")]
        headers += self._security_headers()
        if cookie:
            headers.append(("Set-Cookie", cookie))
        start_response("200 OK", headers)
        events = task.subscribe()

        def line(value):
            return (json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")

        def output():
            deadline = time.monotonic() + 30
            try:
                while True:
                    if cancelled and cancelled.is_set():
                        return
                    try:
                        event = events.get(timeout=0.5)
                        if event["event"] == "_done":
                            break
                        yield line(event)
                    except queue.Empty:
                        pass
                    if task.future.done() and events.empty():
                        break
                    if time.monotonic() > deadline:
                        raise ValueError("Analysis timed out. Try a smaller input.")
                if cancelled and cancelled.is_set():
                    return
                prediction = copy.deepcopy(task.future.result())
                prediction["cached"] = task.cached
                prediction["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
                yield line({"event": "stage", "stage": "saving", "message": "Saving your result in local history."})
                result = self.storage.save_analysis(session["owner"], prediction)
                yield line({"event": "result", "result": result})
            except ValueError as error:
                yield line({"event": "error", "error": {"code": "analysis_failed", "message": str(error)}})
            except Exception:
                log.exception("Analysis or persistence failed")
                yield line({"event": "error", "error": {"code": "analysis_failed", "message": "Analysis could not be completed and saved. Please try again."}})
            finally:
                task.unsubscribe(events)
        return output()

    def _news(self):
        if self._news_cache[0] > time.monotonic():
            return {"items": self._news_cache[1], "cached": True}
        if not self._news_lock.acquire(blocking=False):
            return {"items": self._news_cache[1], "cached": True}
        try:
            items = []
            for source, url in (("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),):
                try:
                    fetched = self.fetcher.fetch(url)
                    raw = fetched["body"]
                    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                        raise ValueError("Unsafe XML feed.")
                    root = ET.fromstring(raw)
                    for item in root.findall(".//item")[:8]:
                        title, link = item.findtext("title"), item.findtext("link")
                        if title and link and urlsplit(link).scheme in ("http", "https"):
                            items.append({"title": title[:250], "link": link, "source": source})
                except Exception as error:
                    log.info("News feed unavailable: %s", type(error).__name__)
            self._news_cache = (time.monotonic() + 3600, items)
            return {"items": items, "cached": False}
        finally:
            self._news_lock.release()

    def __call__(self, environ, start_response):
        started = time.perf_counter()
        method, path = environ.get("REQUEST_METHOD", "GET"), environ.get("PATH_INFO", "/")
        cookie = None
        try:
            if path in self._static and method in ("GET", "HEAD"):
                body, content_type = self._static[path]
                headers = [("Content-Type", content_type), ("Content-Length", str(len(body))),
                           ("Cache-Control", "no-cache" if path == "/" else "public, max-age=3600")]
                start_response("200 OK", headers + self._security_headers())
                return [] if method == "HEAD" else [body]
            if path == "/health" and method == "GET":
                return self._response(start_response, 200, {"ok": True, "version": "2.0.0", "models_loaded": True})
            if not path.startswith("/api/"):
                raise HTTPError(404, "not_found", "This page does not exist.")
            self._check_rate(environ, path)
            session, cookie = self.auth.resolve(environ)
            if path.startswith("/api/admin/") and not session["admin"]:
                raise HTTPError(401, "authentication_required", "Sign in to access administration.")
            if method in ("POST", "PUT", "PATCH", "DELETE"):
                self._check_csrf(environ, session)
            if path == "/api/bootstrap" and method == "GET":
                return self._response(start_response, 200, {
                    "models": self.models.summary(), "capabilities": {"ocr": bool(self.ocr.available), "website_checks": True},
                    "limits": {"max_image_bytes": self.settings.max_image_bytes, "max_text_chars": self.settings.max_text_chars, "max_url_chars": self.settings.max_url_chars},
                    "history": self.storage.history(session["owner"]), "community": self.storage.community(),
                    "csrf_token": self.auth.csrf_token(session), "admin": bool(session["admin"]), "admin_configured": bool(self.auth.credentials)
                }, cookie)
            if path == "/api/analyze" and method == "POST":
                kind, value, inspect = self._analyze_body(environ)
                task = self.pipeline.submit(kind, value, inspect=inspect)
                return self._stream(task, session, start_response, cookie, started, environ.get("awarelink.cancelled"))
            if path == "/api/history" and method == "GET":
                return self._response(start_response, 200, {"history": self.storage.history(session["owner"])}, cookie)
            if path.startswith("/api/analyses/") and method == "GET":
                result = self.storage.shared(path.removeprefix("/api/analyses/"))
                if not result:
                    raise HTTPError(404, "not_found", "This shared result is unavailable.")
                return self._response(start_response, 200, {"result": result}, cookie)
            if path == "/api/feedback" and method == "POST":
                data = self._json_body(environ)
                if not isinstance(data.get("analysis_id"), str) or type(data.get("accurate")) is not bool:
                    raise HTTPError(400, "invalid_feedback", "Select an analysis and an accuracy vote.")
                if not all(isinstance(data.get(key, ""), str) for key in ("reason", "other_text")):
                    raise HTTPError(400, "invalid_feedback", "Feedback must contain text.")
                if len(data.get("reason", "")) > 120 or len(data.get("other_text", "")) > 2000:
                    raise HTTPError(400, "invalid_feedback", "Feedback text is too long.")
                feedback = self.storage.add_feedback(session["owner"], data["analysis_id"], data["accurate"], data.get("reason", ""), data.get("other_text", ""))
                return self._response(start_response, 201, {"ok": True, "feedback": feedback}, cookie)
            if path == "/api/login" and method == "POST":
                data = self._json_body(environ)
                username, password = data.get("username", ""), data.get("password", "")
                if not isinstance(username, str) or not isinstance(password, str) or len(username) > 100 or len(password) > 256:
                    raise HTTPError(400, "invalid_credentials", "Invalid login fields.")
                if not self.auth.credentials:
                    raise HTTPError(503, "admin_unconfigured", "Configure the local admin account before signing in.")
                logged_in = self.auth.login(session, username, password)
                if not logged_in:
                    raise HTTPError(401, "invalid_credentials", "The username or password is incorrect.")
                return self._response(start_response, 200, {"ok": True, "csrf_token": self.auth.csrf_token(logged_in)}, self.auth.cookie(logged_in))
            if path == "/api/logout" and method == "POST":
                anonymous = self.auth.logout(session)
                return self._response(start_response, 200, {"ok": True, "csrf_token": self.auth.csrf_token(anonymous)}, self.auth.cookie(anonymous))
            if path == "/api/admin/overview" and method == "GET":
                data = self.storage.overview()
                data.update(models=self.models.summary(), performance=self.pipeline.metrics)
                return self._response(start_response, 200, data, cookie)
            if path.startswith("/api/admin/analyses/") and method == "DELETE":
                if not self.storage.delete_analysis(path.removeprefix("/api/admin/analyses/")):
                    raise HTTPError(404, "not_found", "Analysis record not found.")
                return self._response(start_response, 200, {"ok": True}, cookie)
            if path.startswith("/api/admin/feedback/") and method == "DELETE":
                if not self.storage.delete_feedback(path.removeprefix("/api/admin/feedback/")):
                    raise HTTPError(404, "not_found", "Feedback record not found.")
                return self._response(start_response, 200, {"ok": True}, cookie)
            if path == "/api/news" and method == "GET":
                return self._response(start_response, 200, self._news(), cookie)
            raise HTTPError(404, "not_found", "This page or endpoint does not exist.")
        except HTTPError as error:
            return self._response(start_response, error.status, {"error": {"code": error.code, "message": error.message}}, cookie,
                                  [("Retry-After", "60")] if error.status == 429 else [])
        except CapacityError as error:
            return self._response(start_response, 503, {"error": {"code": "queue_full", "message": str(error)}}, cookie, [("Retry-After", "2")])
        except ValueError as error:
            return self._response(start_response, 400, {"error": {"code": "invalid_input", "message": str(error)}}, cookie)
        except Exception:
            log.exception("Request failed")
            return self._response(start_response, 500, {"error": {"code": "server_error", "message": "The request could not be completed."}}, cookie)

    def close(self):
        self.pipeline.close()
        if hasattr(self.fetcher, "close"):
            self.fetcher.close()
        self.storage.close()


def create_app(settings=None, models=None, fetcher=None, ocr=None):
    return Application(settings, models, fetcher, ocr)
