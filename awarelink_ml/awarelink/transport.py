"""ASGI transport for incremental HTTP/1.1 streams and connection reuse.

The application remains independently testable as WSGI. A bounded shared
executor runs its blocking sections; the ASGI server owns sockets and framing.
"""
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import asyncio
import io
import json
import threading


class ASGIAdapter:
    def __init__(self, application, workers=None):
        self.application = application
        settings = application.settings
        self.workers = workers or settings.workers + settings.queue_size + 4
        self._executor = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="http")
        self._admission = asyncio.Semaphore(self.workers)
        self._active = set()
        self._closed = False

    async def _error(self, send, status, code, message):
        body = json.dumps({"error": {"code": code, "message": message}}, separators=(",", ":")).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                                (b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff")]})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    def _environ(self, scope, body, cancelled):
        server = scope.get("server") or ("localhost", 80)
        client = scope.get("client") or ("unknown", 0)
        headers = {}
        for key, value in scope.get("headers", []):
            key, value = key.decode("ascii").lower(), value.decode("latin1")
            if key in headers:
                headers[key] += ("; " if key == "cookie" else ",") + value
            else:
                headers[key] = value
        environ = {
            "REQUEST_METHOD": scope.get("method", "GET"), "SCRIPT_NAME": scope.get("root_path", ""),
            "PATH_INFO": scope.get("path", "/").encode("utf-8").decode("latin1"),
            "QUERY_STRING": scope.get("query_string", b"").decode("latin1"),
            "SERVER_NAME": str(server[0]), "SERVER_PORT": str(server[1]),
            "SERVER_PROTOCOL": "HTTP/" + scope.get("http_version", "1.1"), "REMOTE_ADDR": str(client[0]),
            "wsgi.version": (1, 0), "wsgi.url_scheme": scope.get("scheme", "http"),
            "wsgi.input": io.BytesIO(body), "wsgi.errors": io.StringIO(), "wsgi.multithread": True,
            "wsgi.multiprocess": False, "wsgi.run_once": False, "awarelink.cancelled": cancelled,
            "CONTENT_LENGTH": str(len(body)), "CONTENT_TYPE": headers.pop("content-type", "")
        }
        headers.pop("content-length", None)
        for key, value in headers.items():
            environ["HTTP_" + key.upper().replace("-", "_")] = value
        return environ

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await self.aclose()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        if self._closed or self._admission.locked():
            await self._error(send, 503, "server_busy", "The server is busy. Please try again shortly.")
            return
        await self._admission.acquire()
        cancelled = threading.Event()
        self._active.add(cancelled)
        disconnect_task = None
        iterator = None
        response_started = False
        loop = asyncio.get_running_loop()
        try:
            body = bytearray()
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                if message["type"] != "http.request":
                    continue
                body.extend(message.get("body", b""))
                if len(body) > self.application.settings.max_body_bytes:
                    await self._error(send, 413, "body_too_large", "The request exceeds the upload limit.")
                    return
                if not message.get("more_body", False):
                    break
            environ = self._environ(scope, bytes(body), cancelled)
            response = {}

            def start_response(status, headers, exc_info=None):
                if exc_info and response:
                    raise exc_info[1].with_traceback(exc_info[2])
                response["status"] = int(status.split(" ", 1)[0])
                response["headers"] = [(key.lower().encode("ascii"), value.encode("latin1")) for key, value in headers]

            async def watch_disconnect():
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        cancelled.set()
                        return

            disconnect_task = asyncio.create_task(watch_disconnect())
            iterable = await loop.run_in_executor(self._executor, partial(self.application, environ, start_response))
            iterator = iter(iterable)
            if cancelled.is_set():
                return
            if "status" not in response:
                raise RuntimeError("Application did not start its response.")
            await send({"type": "http.response.start", **response})
            response_started = True

            def next_chunk():
                try:
                    return next(iterator)
                except StopIteration:
                    return None

            while not cancelled.is_set():
                chunk = await loop.run_in_executor(self._executor, next_chunk)
                if chunk is None:
                    break
                if not isinstance(chunk, bytes):
                    raise TypeError("WSGI response chunks must be bytes.")
                if not cancelled.is_set():
                    await send({"type": "http.response.body", "body": chunk, "more_body": True})
            if not cancelled.is_set():
                await send({"type": "http.response.body", "body": b"", "more_body": False})
        except asyncio.CancelledError:
            cancelled.set()
            raise
        except Exception:
            cancelled.set()
            if not response_started:
                await self._error(send, 500, "server_error", "The request could not be completed.")
            else:
                raise
        finally:
            cancelled.set()
            if disconnect_task:
                disconnect_task.cancel()
                try:
                    await disconnect_task
                except asyncio.CancelledError:
                    pass
            if iterator and hasattr(iterator, "close"):
                try:
                    await loop.run_in_executor(self._executor, iterator.close)
                except ValueError:
                    # A cancelled transport may still be unwinding its bounded iterator step.
                    pass
            self._active.discard(cancelled)
            self._admission.release()

    def close(self):
        if self._closed:
            return
        self._closed = True
        for cancelled in tuple(self._active):
            cancelled.set()
        self._executor.shutdown(wait=True, cancel_futures=True)
        self.application.close()

    async def aclose(self):
        await asyncio.to_thread(self.close)
