"""Bounded outbound fetches, public-address pinning and reusable HTTP pools."""
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit, urljoin, quote
import ipaddress
import io
import re
import socket
import ssl
import threading
import time

import urllib3

_deadline = threading.local()


class DeadlineSocket:
    """Reapply the remaining absolute budget on EVERY socket read.

    A buffered read/readline can perform many recv calls. An inactivity timeout
    alone can be defeated by slow byte delivery; this wrapper bounds the whole
    fetch while preserving a socket for reuse by the connection pool.
    """
    def __init__(self, sock):
        self._sock = sock
        self._timeout = sock.gettimeout()

    def __getattr__(self, name):
        return getattr(self._sock, name)

    def settimeout(self, timeout):
        self._timeout = timeout
        self._sock.settimeout(timeout)

    def gettimeout(self):
        return self._timeout

    def _budget(self):
        deadline = getattr(_deadline, "value", None)
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("Website check exceeded its total time budget.")
            timeout = min(remaining, self._timeout) if self._timeout is not None else remaining
            self._sock.settimeout(timeout)

    def recv_into(self, buffer, *args):
        self._budget()
        return self._sock.recv_into(buffer, *args)

    def recv(self, size, *args):
        self._budget()
        return self._sock.recv(size, *args)

    def sendall(self, data, *args):
        self._budget()
        return self._sock.sendall(data, *args)

    def makefile(self, mode="rb", buffering=None, **kwargs):
        if mode != "rb":
            raise ValueError("Only binary HTTP reading is supported.")
        parent = self

        class Reader(io.RawIOBase):
            def readable(self):
                return True

            def readinto(self, buffer):
                return parent.recv_into(buffer)

        return io.BufferedReader(Reader(), buffer_size=buffering or io.DEFAULT_BUFFER_SIZE)


class DeadlineHTTPConnection(urllib3.connection.HTTPConnection):
    def connect(self):
        super().connect()
        self.sock = DeadlineSocket(self.sock)


class DeadlineHTTPSConnection(urllib3.connection.HTTPSConnection):
    def connect(self):
        super().connect()
        self.sock = DeadlineSocket(self.sock)


def validate_public_address(value):
    address = ipaddress.ip_address(value)
    if address.version == 6:
        if address.ipv4_mapped:
            validate_public_address(str(address.ipv4_mapped))
        if address in ipaddress.ip_network("2002::/16") or address in ipaddress.ip_network("2001::/32"):
            raise ValueError("IPv6 transition addresses are not accepted.")
    if not address.is_global or address.is_multicast or address.is_reserved or address.is_unspecified:
        raise ValueError("Only public internet destinations are accepted.")
    return str(address)


def normalize_url(url, max_length=2048):
    if not isinstance(url, str) or not url or len(url) > max_length:
        raise ValueError(f"Enter a URL of at most {max_length} characters.")
    if any(ord(character) <= 32 or ord(character) == 127 for character in url) or "\\" in url:
        raise ValueError("URL contains spaces or control characters.")
    if not re.match(r"^https?://", url, re.I):
        if "://" in url or re.match(r"^[a-z][a-z0-9+.-]*:(?!\d+(?:/|$))", url, re.I):
            raise ValueError("Only HTTP and HTTPS URLs are accepted.")
        url = "https://" + url
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            raise ValueError("Invalid URL.")
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            raise ValueError("URLs containing credentials are not accepted.")
        host = parts.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        port = parts.port
        if port not in (None, 80, 443):
            raise ValueError("Only web ports 80 and 443 are accepted.")
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
            raise ValueError("Local destinations are not accepted.")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
                raise ValueError("Invalid hostname.")
            if host.isdigit() or host.startswith("0x") or all(re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", p) for p in host.split(".")):
                raise ValueError("Nonstandard numeric addresses are not accepted.")
        else:
            validate_public_address(str(address))
        scheme = parts.scheme.lower()
        display_host = f"[{host}]" if ":" in host else host
        netloc = display_host + (f":{port}" if port and port != (443 if scheme == "https" else 80) else "")
        path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
        query = quote(parts.query, safe="%:@!$&'()*+,;=/?-._~")
        normalized = urlunsplit((scheme, netloc, path, query, ""))
        if len(normalized) > max_length:
            raise ValueError("Normalized URL is too long.")
        return normalized
    except (UnicodeError, OverflowError) as error:
        raise ValueError("Invalid URL hostname.") from error


class PageText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.size = 0
        self.skip = 0
        self.iframes = 0
        self.password_fields = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self.skip += 1
        if tag == "iframe":
            self.iframes += 1
        if tag == "input" and dict(attrs).get("type", "").lower() == "password":
            self.password_fields += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript"):
            self.skip = max(0, self.skip - 1)

    def handle_data(self, data):
        if not self.skip and self.size < 20_000:
            text = data.strip()[:20_000 - self.size]
            if text:
                self.text.append(text)
                self.size += len(text)


class SafeFetcher:
    def __init__(self, resolver=None, pool_factory=None, total_timeout=10):
        self.resolver = resolver or socket.getaddrinfo
        self.pool_factory = pool_factory
        self.total_timeout = total_timeout
        self._lock = threading.Lock()
        self._dns = OrderedDict()
        self._pools = OrderedDict()
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="dns")
        self._dns_capacity = threading.BoundedSemaphore(4)
        self._ssl = ssl.create_default_context()
        self.closed = False

    def resolve(self, host, port):
        key = (host, port)
        with self._lock:
            cached = self._dns.get(key)
            if cached and cached[0] > time.monotonic():
                self._dns.move_to_end(key)
                return cached[1]
        if not self._dns_capacity.acquire(blocking=False):
            raise ValueError("DNS capacity is busy. Try again later.")
        future = self._executor.submit(self.resolver, host, port, 0, socket.SOCK_STREAM)
        future.add_done_callback(lambda completed: self._dns_capacity.release())
        try:
            remaining = max(0.001, (getattr(_deadline, "value", None) or time.monotonic() + 3) - time.monotonic())
            answers = future.result(timeout=min(3, remaining))
        except TimeoutError as error:
            raise ValueError("Destination lookup timed out.") from error
        if not answers:
            raise ValueError("Destination has no addresses.")
        addresses = list(dict.fromkeys(validate_public_address(answer[4][0]) for answer in answers))
        with self._lock:
            self._dns[key] = (time.monotonic() + 60, addresses[0])
            self._dns.move_to_end(key)
            while len(self._dns) > 64:
                self._dns.popitem(last=False)
        return addresses[0]

    def _pool(self, host, ip, port, scheme):
        key = (scheme, host, ip, port)
        with self._lock:
            if key not in self._pools:
                kwargs = {"host": ip, "port": port, "maxsize": 2, "block": True}
                if scheme == "https":
                    kwargs.update(server_hostname=host, assert_hostname=host, ssl_context=self._ssl, cert_reqs="CERT_REQUIRED")
                factory = self.pool_factory or (urllib3.HTTPSConnectionPool if scheme == "https" else urllib3.HTTPConnectionPool)
                self._pools[key] = factory(**kwargs)
                if not self.pool_factory:
                    self._pools[key].ConnectionCls = DeadlineHTTPSConnection if scheme == "https" else DeadlineHTTPConnection
                while len(self._pools) > 32:
                    _, pool = self._pools.popitem(last=False)
                    pool.close()
            self._pools.move_to_end(key)
            return self._pools[key]

    def fetch(self, url, max_bytes=262_144, max_redirects=3):
        previous = getattr(_deadline, "value", None)
        _deadline.value = time.monotonic() + self.total_timeout
        try:
            return self._fetch(url, max_bytes, max_redirects)
        finally:
            _deadline.value = previous

    def _fetch(self, url, max_bytes, max_redirects):
        if self.closed:
            raise RuntimeError("Fetcher is closed.")
        current = normalize_url(url)
        deadline = _deadline.value
        for hop in range(max_redirects + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("Website check exceeded its time budget.")
            parts = urlsplit(current)
            host = parts.hostname
            port = parts.port or (443 if parts.scheme == "https" else 80)
            ip = self.resolve(host, port)
            pool = self._pool(host, ip, port, parts.scheme)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("Website check exceeded its time budget.")
            response = pool.request("GET", urlunsplit(("", "", parts.path, parts.query, "")),
                headers={"Host": parts.netloc, "User-Agent": "AwareLink/2.0 (bounded security inspection)",
                         "Accept": "text/html,application/xml,text/xml,text/plain", "Accept-Encoding": "identity"},
                redirect=False, retries=False, preload_content=False, decode_content=False,
                timeout=urllib3.Timeout(total=remaining, connect=min(3, remaining), read=min(3, remaining)),
                pool_timeout=min(2, remaining), assert_same_host=False)
            fully_read = False
            try:
                if response.status in (301, 302, 303, 307, 308):
                    destination = response.headers.get("Location")
                    if not destination or hop == max_redirects:
                        raise ValueError("Website has too many or invalid redirects.")
                    next_url = normalize_url(urljoin(current, destination))
                    if parts.scheme == "https" and urlsplit(next_url).scheme != "https":
                        raise ValueError("HTTPS downgrade redirect was rejected.")
                    current = next_url
                    continue
                declared = response.headers.get("Content-Length")
                if declared and (not declared.isdigit() or int(declared) > max_bytes):
                    raise ValueError("Website response is too large.")
                if response.headers.get("Content-Encoding", "identity").lower() not in ("identity", ""):
                    raise ValueError("Compressed responses are not accepted for inspection.")
                chunks, size = [], 0
                while True:
                    if time.monotonic() > deadline:
                        raise ValueError("Website check exceeded its time budget.")
                    chunk = response.read(min(16_384, max_bytes + 1 - size), decode_content=False)
                    if not chunk:
                        fully_read = True
                        break
                    size += len(chunk)
                    if size > max_bytes:
                        raise ValueError("Website response is too large.")
                    chunks.append(chunk)
                return {"url": current, "status": response.status, "headers": dict(response.headers), "body": b"".join(chunks)}
            finally:
                if not fully_read:
                    response.close()
                response.release_conn()
        raise ValueError("Redirect limit exceeded.")

    def inspect(self, url):
        response = self.fetch(url)
        content_type = next((value for key, value in response["headers"].items() if key.lower() == "content-type"), "")
        if content_type and not any(value in content_type.lower() for value in ("text/html", "text/plain", "application/xhtml")):
            raise ValueError("The destination did not return a web page.")
        parser = PageText()
        parser.feed(response["body"].decode("utf-8", errors="replace"))
        headers = {key.lower(): value for key, value in response["headers"].items()}
        return {"url": response["url"], "status": response["status"],
                "tls_verified": urlsplit(response["url"]).scheme == "https",
                "missing_headers": [header for header in ("content-security-policy", "x-content-type-options", "x-frame-options") if header not in headers],
                "iframes": parser.iframes, "password_fields": parser.password_fields, "page_text": " ".join(parser.text)}

    def close(self):
        self.closed = True
        self._executor.shutdown(wait=False, cancel_futures=True)
        with self._lock:
            for pool in self._pools.values():
                pool.close()
            self._pools.clear()
