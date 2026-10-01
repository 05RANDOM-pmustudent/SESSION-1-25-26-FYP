"""Offline regression tests for untrusted inputs and administrative access."""

import io
import json
import http.client
import socket
import struct
import subprocess
import tempfile
import time
import unittest
import zlib
from collections import deque
from pathlib import Path
from unittest.mock import patch

from awarelink.network import SafeFetcher, normalize_url, validate_public_address
from awarelink.auth import Auth
from awarelink.config import Settings
from awarelink.storage import Store


class PublicDestinationTests(unittest.TestCase):
    def test_private_local_reserved_and_mapped_addresses_are_rejected(self):
        blocked = (
            "127.0.0.1", "127.99.2.3", "10.2.3.4", "172.16.0.1",
            "192.168.10.2", "169.254.169.254", "100.64.0.1", "0.0.0.0",
            "192.0.2.1", "198.51.100.1", "203.0.113.1", "224.0.0.1",
            "240.0.0.1", "255.255.255.255", "::", "::1", "fe80::1",
            "fc00::1", "ff02::1", "2001:db8::1", "::ffff:127.0.0.1",
            "::ffff:10.2.3.4", "::ffff:169.254.169.254",
        )
        for address in blocked:
            with self.subTest(address=address), self.assertRaises(ValueError):
                validate_public_address(address)

    def test_public_unicast_addresses_are_accepted_without_network_work(self):
        for address in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
            with self.subTest(address=address):
                self.assertIsInstance(validate_public_address(address), str)

    def test_url_rejects_credentials_schemes_bad_ports_and_controls(self):
        blocked = (
            "file:///etc/passwd", "ftp://example.com/file", "javascript:alert(1)",
            "http://user:password@example.com", "https://example.com:0/",
            "https://example.com:65536/", "https://example.com:bad/",
            "https://example.com/\r\nInjected: header", "https://example.com/\x00",
        )
        for url in blocked:
            with self.subTest(url=url), self.assertRaises(ValueError):
                normalize_url(url)

    def test_url_size_is_bounded_before_dns(self):
        with self.assertRaises(ValueError):
            normalize_url("https://example.com/" + "x" * 200, max_length=80)

    def test_ipv6_transition_addresses_cannot_hide_private_destinations(self):
        for address in ("2002:7f00:1::", "2002:0a00:1::", "2001::7f00:1"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                validate_public_address(address)

    def test_dns_rejects_mixed_public_and_private_answers(self):
        def resolver(host, port, *args, **kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
            ]

        fetcher = SafeFetcher(resolver=resolver)
        try:
            with self.assertRaises(ValueError):
                fetcher.resolve("mixed.example", 443)
        finally:
            fetcher.close()


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b"ok"):
        self.status, self.headers = status, headers or {}
        self.body = io.BytesIO(body)
        self.closed = False
        self.released = False

    def read(self, amount, **kwargs):
        return self.body.read(amount)

    def close(self):
        self.closed = True

    def release_conn(self):
        self.released = True


class OfflinePoolFactory:
    def __init__(self, responses):
        self.responses = deque(responses)
        self.configurations = []
        self.requests = []
        self.closes = 0

    def __call__(self, **configuration):
        self.configurations.append(configuration)
        factory = self

        class Pool:
            def request(self, method, target, **kwargs):
                factory.requests.append((method, target, kwargs))
                return factory.responses.popleft()

            def close(self):
                factory.closes += 1

        return Pool()


class OutboundFetchTests(unittest.TestCase):
    def make_fetcher(self, responses, addresses=None):
        self.resolved = []
        addresses = addresses or {}

        def resolver(host, port, *args, **kwargs):
            self.resolved.append(host)
            ip = addresses.get(host, "8.8.8.8")
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

        factory = OfflinePoolFactory(responses)
        fetcher = SafeFetcher(resolver=resolver, pool_factory=factory)
        self.addCleanup(fetcher.close)
        return fetcher, factory

    def test_actual_connection_is_pinned_and_tls_and_host_identity_are_preserved(self):
        response = FakeResponse(body=b"hello")
        fetcher, factory = self.make_fetcher([response])
        self.assertEqual(fetcher.fetch("https://example.com/path?q=1")["body"], b"hello")
        configuration = factory.configurations[0]
        self.assertEqual(configuration["host"], "8.8.8.8")
        self.assertEqual(configuration["server_hostname"], "example.com")
        self.assertEqual(configuration["assert_hostname"], "example.com")
        self.assertEqual(configuration["cert_reqs"], "CERT_REQUIRED")
        request = factory.requests[0]
        self.assertEqual(request[1], "/path?q=1")
        self.assertEqual(request[2]["headers"]["Host"], "example.com")
        self.assertFalse(request[2]["redirect"])
        self.assertFalse(request[2]["retries"])
        self.assertTrue(response.released)
        self.assertFalse(response.closed)

    def test_redirect_to_private_ip_is_rejected_before_second_request(self):
        response = FakeResponse(302, {"Location": "http://127.0.0.1/admin"})
        fetcher, factory = self.make_fetcher([response])
        with self.assertRaises(ValueError):
            fetcher.fetch("http://example.com/")
        self.assertEqual(len(factory.requests), 1)
        self.assertTrue(response.closed)
        self.assertTrue(response.released)

    def test_redirect_hostname_is_resolved_and_checked_independently(self):
        response = FakeResponse(302, {"Location": "https://internal.example/"})
        fetcher, factory = self.make_fetcher([response], {"internal.example": "10.0.0.1"})
        with self.assertRaises(ValueError):
            fetcher.fetch("https://example.com/")
        self.assertEqual(self.resolved, ["example.com", "internal.example"])
        self.assertEqual(len(factory.requests), 1)

    def test_response_limits_cover_declared_and_actual_body_and_compression(self):
        cases = (
            FakeResponse(headers={"Content-Length": "1000"}, body=b"x"),
            FakeResponse(body=b"x" * 33),
            FakeResponse(headers={"Content-Encoding": "gzip"}, body=b"compressed"),
        )
        for response in cases:
            with self.subTest(headers=response.headers):
                fetcher, factory = self.make_fetcher([response])
                with self.assertRaises(ValueError):
                    fetcher.fetch("https://example.com/", max_bytes=32)
                self.assertTrue(response.closed)
                self.assertTrue(response.released)

    def test_redirect_count_and_https_downgrade_are_bounded(self):
        responses = [FakeResponse(302, {"Location": "/next"}) for _ in range(3)]
        fetcher, factory = self.make_fetcher(responses)
        with self.assertRaises(ValueError):
            fetcher.fetch("https://example.com/", max_redirects=2)
        self.assertEqual(len(factory.requests), 3)
        self.assertTrue(all(response.closed and response.released for response in responses))
        fetcher, factory = self.make_fetcher([FakeResponse(302, {"Location": "http://example.com/"})])
        with self.assertRaises(ValueError):
            fetcher.fetch("https://example.com/")
        self.assertEqual(len(factory.requests), 1)

    def test_repeated_host_reuses_dns_and_connection_pool(self):
        fetcher, factory = self.make_fetcher([FakeResponse(), FakeResponse()])
        fetcher.fetch("https://example.com/one")
        fetcher.fetch("https://example.com/two")
        self.assertEqual(self.resolved, ["example.com"])
        self.assertEqual(len(factory.configurations), 1)
        self.assertEqual(len(factory.requests), 2)

    def test_dns_rejects_private_ipv6_answers(self):
        def resolver(host, port, *args, **kwargs):
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:10.0.0.1", port, 0, 0))]

        fetcher = SafeFetcher(resolver=resolver)
        try:
            with self.assertRaises(ValueError):
                fetcher.resolve("private-v6.example", 443)
        finally:
            fetcher.close()


def wsgi_request(app, method="GET", path="/api/bootstrap", data=None,
                 raw=None, cookie="", headers=None, content_type="application/json",
                 content_length=None, stream=False):
    """Exercise the WSGI boundary without binding a socket or calling a service."""
    if raw is None:
        raw = json.dumps(data).encode("utf-8") if data is not None else b""
    response = {}
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path.split("?", 1)[0],
        "QUERY_STRING": path.split("?", 1)[1] if "?" in path else "",
        "SERVER_NAME": "localhost", "SERVER_PORT": "8765",
        "SERVER_PROTOCOL": "HTTP/1.1", "REMOTE_ADDR": "127.0.0.1",
        "wsgi.version": (1, 0), "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(raw), "wsgi.errors": io.StringIO(),
        "wsgi.multithread": True, "wsgi.multiprocess": False,
        "wsgi.run_once": False, "HTTP_HOST": "localhost:8765",
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": str(len(raw) if content_length is None else content_length),
    }
    if cookie:
        environ["HTTP_COOKIE"] = cookie
    for name, value in (headers or {}).items():
        environ["HTTP_" + name.upper().replace("-", "_")] = value

    def start_response(status, response_headers, exc_info=None):
        response["status"] = int(status.split(" ", 1)[0])
        response["headers"] = response_headers

    iterable = app(environ, start_response)
    if stream:
        response["iterator"] = iter(iterable)
        response["close"] = getattr(iterable, "close", lambda: None)
        return response
    try:
        response["body"] = b"".join(iterable)
    finally:
        close = getattr(iterable, "close", None)
        if close:
            close()
    response["json"] = None
    try:
        response["json"] = json.loads(response["body"])
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return response


def response_cookie(response):
    cookies = [value.split(";", 1)[0] for name, value in response["headers"]
               if name.lower() == "set-cookie"]
    return "; ".join(cookies)


class SessionSecurityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.settings = Settings(data_dir=Path(self.directory.name),
                                 admin_password="correct horse battery staple")
        self.path = self.settings.data_dir / "test.db"
        self.store = Store(self.path)
        self.auth = Auth(self.settings, self.store)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def session(self):
        return self.auth.resolve({})[0]

    def test_secret_and_sessions_survive_application_restart(self):
        anonymous = self.session()
        admin = self.auth.login(anonymous, "admin", "correct horse battery staple")
        cookie = self.auth.cookie(admin).split(";", 1)[0]
        original_secret = self.auth.secret
        self.store.close()
        self.store = Store(self.path)
        self.auth = Auth(self.settings, self.store)
        recovered, new_cookie = self.auth.resolve({"HTTP_COOKIE": cookie})
        self.assertEqual(self.auth.secret, original_secret)
        self.assertEqual(recovered["id"], admin["id"])
        self.assertTrue(recovered["admin"])
        self.assertIsNone(new_cookie)

    def test_login_rotates_session_and_logout_revokes_admin_cookie(self):
        anonymous = self.session()
        admin = self.auth.login(anonymous, "admin", "correct horse battery staple")
        self.assertNotEqual(anonymous["id"], admin["id"])
        self.assertEqual(anonymous["owner"], admin["owner"])
        self.assertIsNone(self.store.get_session(anonymous["id"]))
        self.assertFalse(self.auth.csrf_valid(admin, self.auth.csrf_token(anonymous)))
        after_logout = self.auth.logout(admin)
        self.assertFalse(after_logout["admin"])
        self.assertEqual(after_logout["owner"], anonymous["owner"])
        self.assertIsNone(self.store.get_session(admin["id"]))

    def test_tampered_and_expired_cookies_never_restore_admin_access(self):
        admin = self.auth.login(self.session(), "admin", "correct horse battery staple")
        cookie = self.auth.cookie(admin).split(";", 1)[0]
        tampered = cookie[:-1] + ("0" if cookie[-1] != "0" else "1")
        recovered, _ = self.auth.resolve({"HTTP_COOKIE": tampered})
        self.assertFalse(recovered["admin"])
        self.store.connection().execute("UPDATE sessions SET expires=0 WHERE id=?", (admin["id"],))
        self.store.connection().commit()
        recovered, _ = self.auth.resolve({"HTTP_COOKIE": cookie})
        self.assertFalse(recovered["admin"])

    def test_csrf_rejects_wrong_session_wrong_types_and_non_ascii(self):
        first, second = self.session(), self.session()
        self.assertTrue(self.auth.csrf_valid(first, self.auth.csrf_token(first)))
        for token in (None, 1, b"token", "", "wrong", "é", self.auth.csrf_token(second)):
            with self.subTest(token=token):
                self.assertFalse(self.auth.csrf_valid(first, token))

    def test_cookie_flags_and_disabled_or_incorrect_login(self):
        session = self.session()
        cookie = self.auth.cookie(session)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.settings.secure_cookie = True
        self.assertIn("Secure", self.auth.cookie(session))
        self.assertIsNone(self.auth.login(session, "admin", "wrong password"))
        self.assertIsNone(self.auth.login(session, "different user", "correct horse battery staple"))
        self.auth.credentials = None
        self.assertIsNone(self.auth.login(session, "admin", "correct horse battery staple"))


class ApplicationSecurityTests(unittest.TestCase):
    def setUp(self):
        from awarelink.app import create_app
        from test_flow import FakeFetcher, FakeModels, FakeOCR

        self.directory = tempfile.TemporaryDirectory()
        self.models = FakeModels()
        self.settings = Settings(
            data_dir=Path(self.directory.name), secret="s" * 48,
            admin_password="correct horse battery staple", workers=1, queue_size=2,
            max_body_bytes=1024, max_image_bytes=512, max_text_chars=200,
            max_url_chars=80, request_limit=1000,
        )
        self.app = create_app(self.settings, models=self.models,
                              fetcher=FakeFetcher(), ocr=FakeOCR())
        bootstrap = wsgi_request(self.app)
        self.assertEqual(bootstrap["status"], 200)
        self.cookie = response_cookie(bootstrap)
        self.csrf = bootstrap["json"]["csrf_token"]

    def tearDown(self):
        self.app.close()
        self.directory.cleanup()

    def request(self, method, path, data=None, raw=None, csrf=True,
                cookie=None, headers=None, **kwargs):
        request_headers = dict(headers or {})
        if csrf:
            request_headers["X-CSRF-Token"] = self.csrf if csrf is True else csrf
        return wsgi_request(self.app, method, path, data=data, raw=raw,
                            cookie=self.cookie if cookie is None else cookie,
                            headers=request_headers, **kwargs)

    def login(self):
        response = self.request("POST", "/api/login", {
            "username": "admin", "password": "correct horse battery staple"})
        self.assertEqual(response["status"], 200)
        self.cookie = response_cookie(response)
        self.csrf = response["json"]["csrf_token"]
        return response

    def test_all_administrative_reads_and_deletes_require_admin(self):
        for method, route in (
            ("GET", "/api/admin/overview"),
            ("DELETE", "/api/admin/analyses/nonexistent"),
            ("DELETE", "/api/admin/feedback/nonexistent"),
        ):
            with self.subTest(method=method, route=route):
                response = self.request(method, route)
                self.assertEqual(response["status"], 401)
        self.assertEqual(self.app.storage.overview()["stats"]["total"], 0)

    def test_mutations_require_session_csrf_even_for_public_features(self):
        for route, data in (
            ("/api/analyze", {"kind": "news", "input": "A valid sample news report."}),
            ("/api/feedback", {"analysis_id": "any", "accurate": True}),
            ("/api/login", {"username": "admin", "password": "correct horse battery staple"}),
            ("/api/logout", {}),
        ):
            for token in (False, "wrong", "é"):
                with self.subTest(route=route, token=token):
                    response = self.request("POST", route, data, csrf=token)
                    self.assertEqual(response["status"], 403)
        self.assertEqual(self.models.calls, [])

    def test_authenticated_delete_requires_csrf_and_logout_revokes_access(self):
        old_cookie, old_csrf = self.cookie, self.csrf
        self.login()
        self.assertNotEqual(self.cookie, old_cookie)
        self.assertNotEqual(self.csrf, old_csrf)
        self.assertEqual(self.request("GET", "/api/admin/overview")["status"], 200)
        for token in (False, old_csrf, "wrong"):
            response = self.request("DELETE", "/api/admin/analyses/nonexistent", csrf=token)
            self.assertEqual(response["status"], 403)
        stale_cookie = self.cookie
        logout = self.request("POST", "/api/logout", {})
        self.assertEqual(logout["status"], 200)
        denied = self.request("GET", "/api/admin/overview", cookie=stale_cookie)
        self.assertEqual(denied["status"], 401)

    def test_input_and_request_limits_reject_before_inference(self):
        invalid = (
            {"kind": "news", "input": "n" * 201},
            {"kind": "url", "input": "https://example.com/" + "u" * 80},
            {"kind": "news", "input": ["not a string"]},
            {"kind": "unknown", "input": "Unknown analysis type"},
        )
        for data in invalid:
            with self.subTest(data=data):
                response = self.request("POST", "/api/analyze", data)
                self.assertIn(response["status"], (400, 413))
        for raw, declared in ((b"", 1025), (b"x" * 1025, None)):
            response = self.request("POST", "/api/analyze", raw=raw,
                                    content_length=declared)
            self.assertEqual(response["status"], 413)
        self.assertEqual(self.models.calls, [])
        self.assertEqual(self.app.storage.overview()["stats"]["total"], 0)

    def test_malformed_json_returns_client_error_without_inference(self):
        response = self.request("POST", "/api/analyze", raw=b"{invalid JSON")
        self.assertEqual(response["status"], 400)
        self.assertEqual(self.models.calls, [])

    def test_upload_has_separate_size_limit_before_ocr_or_inference(self):
        boundary = "awarelink-test-boundary"
        body = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"kind\"\r\n\r\nscreenshot\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sample.png\"\r\n"
            "Content-Type: image/png\r\n\r\n"
        ).encode() + b"x" * 513 + f"\r\n--{boundary}--\r\n".encode()
        self.assertLess(len(body), self.settings.max_body_bytes)
        response = self.request("POST", "/api/analyze", raw=body,
                                content_type=f"multipart/form-data; boundary={boundary}")
        self.assertIn(response["status"], (400, 413))
        self.assertEqual(self.models.calls, [])

    def test_bad_credentials_do_not_grant_access(self):
        response = self.request("POST", "/api/login", {
            "username": "admin", "password": "wrong password"})
        self.assertEqual(response["status"], 401)
        self.assertEqual(self.request("GET", "/api/admin/overview")["status"], 401)

    def test_valid_csrf_still_rejects_cross_site_origin_and_fetch_metadata(self):
        data = {"kind": "news", "input": "A valid sample report from another website."}
        for headers in ({"Origin": "https://attacker.example"}, {"Sec-Fetch-Site": "cross-site"}):
            with self.subTest(headers=headers):
                response = self.request("POST", "/api/analyze", data, headers=headers)
                self.assertEqual(response["status"], 403)
        self.assertEqual(self.models.calls, [])

    def test_incomplete_body_and_wrong_content_type_are_client_errors(self):
        response = self.request("POST", "/api/analyze", raw=b"{}", content_length=100)
        self.assertEqual(response["status"], 400)
        response = self.request("POST", "/api/analyze", raw=b"{}", content_type="text/plain")
        self.assertEqual(response["status"], 415)
        self.assertEqual(self.models.calls, [])

    def test_many_multipart_fields_are_rejected_before_mime_parser_allocations(self):
        boundary = "small-test-boundary"
        body = b"".join(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"field{index}\"\r\n\r\nx\r\n".encode()
            for index in range(6)
        ) + f"--{boundary}--\r\n".encode()
        self.assertLess(len(body), self.settings.max_body_bytes)
        with patch("awarelink.app.BytesParser") as parser:
            response = self.request("POST", "/api/analyze", raw=body,
                content_type=f"multipart/form-data; boundary={boundary}")
        self.assertEqual(response["status"], 400)
        parser.assert_not_called()
        self.assertEqual(self.models.calls, [])

    def test_unknown_non_api_paths_do_not_create_persistent_sessions(self):
        before = self.app.storage.connection().execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        for path in ("/unknown", "/robots.txt", "/missing.css"):
            response = wsgi_request(self.app, path=path)
            self.assertEqual(response["status"], 404)
            self.assertEqual(response_cookie(response), "")
        after = self.app.storage.connection().execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        self.assertEqual(before, after)


class LocalOCRSecurityTests(unittest.TestCase):
    @staticmethod
    def image_bytes(size=(64, 32), format="PNG"):
        from PIL import Image
        buffer = io.BytesIO()
        Image.new("RGB", size, color="white").save(buffer, format=format)
        return buffer.getvalue()

    def test_invalid_unsupported_and_too_small_images_are_rejected(self):
        from awarelink.ocr import LocalOCR
        valid = self.image_bytes()
        LocalOCR.validate(valid)
        for data in (b"not an image", b"<svg></svg>", self.image_bytes(format="GIF"),
                     self.image_bytes(size=(23, 32))):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                LocalOCR.validate(data)

    def test_image_pixel_limit_is_checked_from_header_before_decoding(self):
        from awarelink.ocr import LocalOCR
        data = bytearray(self.image_bytes())
        # Change the PNG IHDR dimensions and repair its CRC. The small input
        # remains bounded while claiming an image requiring a large allocation.
        data[16:24] = struct.pack(">II", 4000, 4000)
        data[29:33] = struct.pack(">I", zlib.crc32(data[12:29]) & 0xffffffff)
        with self.assertRaises(ValueError):
            LocalOCR.validate(bytes(data))

    def test_ocr_subprocess_has_timeout_and_bounded_parallelism_without_shell(self):
        from awarelink.ocr import LocalOCR
        ocr = LocalOCR.__new__(LocalOCR)
        ocr.available = True
        ocr.command = "offline-test-tesseract"
        with patch("awarelink.ocr.subprocess.run", side_effect=subprocess.TimeoutExpired("ocr", 12)) as run:
            with self.assertRaisesRegex(ValueError, "timed out"):
                ocr.extract(self.image_bytes())
        args, kwargs = run.call_args
        self.assertIsInstance(args[0], list)
        self.assertGreater(kwargs["timeout"], 0)
        self.assertLessEqual(kwargs["timeout"], 30)
        self.assertFalse(kwargs.get("shell", False))
        self.assertEqual(kwargs["env"]["OMP_THREAD_LIMIT"], "1")


class SlowByteSocket:
    """Offline socket that keeps making progress inside an inactivity timeout."""
    def __init__(self, data, slow_after=0, delay=0.02):
        self.data = data
        self.position = 0
        self.slow_after, self.delay = slow_after, delay
        self.timeout = 3.0
        self.timeouts = []

    def gettimeout(self):
        return self.timeout

    def settimeout(self, value):
        self.timeout = value
        self.timeouts.append(value)

    def recv_into(self, buffer, *args):
        if self.position >= len(self.data):
            return 0
        if self.position >= self.slow_after:
            wait = min(self.delay, self.timeout) if self.timeout is not None else self.delay
            time.sleep(max(wait, 0))
            if self.timeout is not None and self.timeout <= self.delay:
                raise socket.timeout("Offline inactivity timeout")
        buffer[0] = self.data[self.position]
        self.position += 1
        return 1


class AbsoluteNetworkDeadlineTests(unittest.TestCase):
    def check_slow_response(self, slow_headers):
        from awarelink.network import DeadlineSocket, _deadline
        headers = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
        data = headers + b"x" * 100
        sock = SlowByteSocket(data, slow_after=0 if slow_headers else len(headers))
        wrapped = DeadlineSocket(sock)
        started = time.monotonic()
        response = http.client.HTTPResponse(wrapped)
        try:
            with patch.object(_deadline, "value", started + 0.10, create=True):
                with self.assertRaises(socket.timeout):
                    response.begin()
                    response.read(100)
        finally:
            response.close()
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.40)
        self.assertLess(sock.position, len(data))
        self.assertGreater(len(sock.timeouts), 1)
        self.assertLess(sock.timeouts[-1], sock.timeouts[0])

    def test_total_deadline_interrupts_continuously_dripping_http_headers(self):
        self.check_slow_response(slow_headers=True)

    def test_total_deadline_interrupts_continuously_dripping_buffered_body(self):
        self.check_slow_response(slow_headers=False)


if __name__ == "__main__":
    unittest.main()
