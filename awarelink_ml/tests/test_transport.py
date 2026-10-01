"""ASGI framing, bounded admission and cancellation tests without sockets."""

import asyncio
import json
import threading
import unittest
from types import SimpleNamespace

from awarelink.transport import ASGIAdapter


class FakeApplication:
    def __init__(self, max_body_bytes=32):
        self.settings = SimpleNamespace(workers=1, queue_size=0,
                                        max_body_bytes=max_body_bytes)
        self.calls = []
        self.closed = False
        self.handler = None

    def __call__(self, environ, start_response):
        self.calls.append(environ)
        if self.handler:
            return self.handler(environ, start_response)
        start_response("200 OK", [("Content-Type", "text/plain"), ("X-Test", "forwarded")])
        return [b"ok"]

    def close(self):
        self.closed = True


class Exchange:
    def __init__(self, messages=None, **overrides):
        self.scope = {
            "type": "http", "http_version": "1.1", "method": "GET",
            "scheme": "http", "path": "/api/bootstrap", "root_path": "",
            "query_string": b"", "headers": [(b"host", b"localhost:8765")],
            "server": ("127.0.0.1", 8765), "client": ("127.0.0.1", 12345),
        }
        self.scope.update(overrides)
        self.incoming = asyncio.Queue()
        for message in messages if messages is not None else [{"type": "http.request", "body": b"", "more_body": False}]:
            self.incoming.put_nowait(message)
        self.sent = []
        self.first_body = asyncio.Event()

    async def receive(self):
        return await self.incoming.get()

    async def send(self, message):
        self.sent.append(message)
        if message["type"] == "http.response.body" and message.get("body"):
            self.first_body.set()

    async def run(self, adapter):
        await adapter(self.scope, self.receive, self.send)

    def status(self):
        return next(message["status"] for message in self.sent if message["type"] == "http.response.start")

    def body(self):
        return b"".join(message.get("body", b"") for message in self.sent if message["type"] == "http.response.body")


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.application = FakeApplication()
        self.adapter = ASGIAdapter(self.application, workers=1)

    async def asyncTearDown(self):
        await self.adapter.aclose()

    async def test_wsgi_auth_headers_query_and_body_are_forwarded(self):
        exchange = Exchange(
            messages=[{"type": "http.request", "body": b"first", "more_body": True},
                      {"type": "http.request", "body": b"second", "more_body": False}],
            method="POST", path="/api/analyze", scheme="https",
            query_string=b"kind=news&x=1", headers=[
                (b"host", b"local.example"), (b"content-type", b"application/json"),
                (b"x-csrf-token", b"session-specific-token"),
                (b"cookie", b"awarelink_session=signed"), (b"cookie", b"other=value"),
                (b"origin", b"https://local.example"),
            ])
        await asyncio.wait_for(exchange.run(self.adapter), timeout=2)
        environ = self.application.calls[0]
        self.assertEqual(environ["HTTP_X_CSRF_TOKEN"], "session-specific-token")
        self.assertEqual(environ["HTTP_COOKIE"], "awarelink_session=signed; other=value")
        self.assertEqual(environ["HTTP_ORIGIN"], "https://local.example")
        self.assertEqual(environ["HTTP_HOST"], "local.example")
        self.assertEqual(environ["CONTENT_TYPE"], "application/json")
        self.assertEqual(environ["CONTENT_LENGTH"], "11")
        self.assertEqual(environ["wsgi.input"].read(), b"firstsecond")
        self.assertEqual(environ["QUERY_STRING"], "kind=news&x=1")
        self.assertEqual(environ["wsgi.url_scheme"], "https")
        self.assertIsInstance(environ["awarelink.cancelled"], threading.Event)
        self.assertEqual(exchange.status(), 200)

    async def test_cumulative_body_limit_rejects_before_calling_application(self):
        self.application.settings.max_body_bytes = 8
        exchange = Exchange(messages=[
            {"type": "http.request", "body": b"123456", "more_body": True},
            {"type": "http.request", "body": b"789012", "more_body": False},
        ], method="POST")
        await asyncio.wait_for(exchange.run(self.adapter), timeout=2)
        self.assertEqual(exchange.status(), 413)
        self.assertEqual(self.application.calls, [])
        self.assertIn("error", json.loads(exchange.body()))
        self.assertFalse(exchange.sent[-1]["more_body"])

    async def test_disconnect_during_upload_does_not_run_application(self):
        exchange = Exchange(messages=[
            {"type": "http.request", "body": b"part", "more_body": True},
            {"type": "http.disconnect"},
        ], method="POST")
        await asyncio.wait_for(exchange.run(self.adapter), timeout=2)
        self.assertEqual(self.application.calls, [])
        self.assertEqual(exchange.sent, [])

    async def test_ndjson_chunks_are_incremental_and_end_one_response(self):
        gate = threading.Event()
        closed = threading.Event()

        def handler(environ, start_response):
            start_response("200 OK", [("Content-Type", "application/x-ndjson"),
                                       ("Set-Cookie", "first=one"), ("Set-Cookie", "second=two")])

            def output():
                try:
                    yield b'{"event":"stage","stage":"queued"}\n'
                    if not gate.wait(timeout=2):
                        raise RuntimeError("Test stream was not released")
                    yield b'{"event":"result","result":{"id":"saved"}}\n'
                finally:
                    closed.set()
            return output()

        self.application.handler = handler
        exchange = Exchange()
        running = asyncio.create_task(exchange.run(self.adapter))
        try:
            await asyncio.wait_for(exchange.first_body.wait(), timeout=1)
            self.assertFalse(running.done())
            self.assertEqual(exchange.sent[1]["more_body"], True)
            gate.set()
            await asyncio.wait_for(running, timeout=2)
        finally:
            gate.set()
            if not running.done():
                await asyncio.wait_for(running, timeout=2)
        starts = [message for message in exchange.sent if message["type"] == "http.response.start"]
        self.assertEqual(len(starts), 1)
        self.assertEqual([value for key, value in starts[0]["headers"] if key == b"set-cookie"],
                         [b"first=one", b"second=two"])
        self.assertFalse(exchange.sent[-1]["more_body"])
        self.assertEqual(exchange.sent[-1]["body"], b"")
        self.assertEqual([json.loads(line)["event"] for line in exchange.body().splitlines()], ["stage", "result"])
        self.assertTrue(closed.is_set())

    async def test_disconnect_sets_cancellation_closes_stream_and_releases_admission(self):
        closed = threading.Event()

        def handler(environ, start_response):
            start_response("200 OK", [("Content-Type", "application/x-ndjson")])

            def output():
                try:
                    yield b'{"event":"stage"}\n'
                    if not environ["awarelink.cancelled"].wait(timeout=2):
                        raise RuntimeError("Cancellation was not propagated")
                finally:
                    closed.set()
            return output()

        self.application.handler = handler
        exchange = Exchange()
        running = asyncio.create_task(exchange.run(self.adapter))
        await asyncio.wait_for(exchange.first_body.wait(), timeout=1)
        exchange.incoming.put_nowait({"type": "http.disconnect"})
        await asyncio.wait_for(running, timeout=2)
        self.assertTrue(self.application.calls[0]["awarelink.cancelled"].is_set())
        self.assertTrue(closed.is_set())
        self.assertEqual(sum(message["type"] == "http.response.body" for message in exchange.sent), 1)
        self.application.handler = None
        next_request = Exchange()
        await asyncio.wait_for(next_request.run(self.adapter), timeout=2)
        self.assertEqual(next_request.status(), 200)

    async def test_transport_admission_rejects_excess_work_without_executor_queue(self):
        gate = threading.Event()
        entered = threading.Event()

        def handler(environ, start_response):
            entered.set()
            if not gate.wait(timeout=2):
                raise RuntimeError("Test worker was not released")
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"done"]

        self.application.handler = handler
        first = Exchange()
        running = asyncio.create_task(first.run(self.adapter))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 1))
            excess = Exchange()
            await asyncio.wait_for(excess.run(self.adapter), timeout=1)
            self.assertEqual(excess.status(), 503)
            self.assertEqual(len(self.application.calls), 1)
        finally:
            gate.set()
            await asyncio.wait_for(running, timeout=2)
        self.assertEqual(first.status(), 200)

    async def test_lifespan_startup_and_shutdown_close_shared_resources(self):
        exchange = Exchange(messages=[{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}],
                            type="lifespan")
        await asyncio.wait_for(exchange.run(self.adapter), timeout=2)
        self.assertEqual([message["type"] for message in exchange.sent],
                         ["lifespan.startup.complete", "lifespan.shutdown.complete"])
        self.assertTrue(self.application.closed)


if __name__ == "__main__":
    unittest.main()
