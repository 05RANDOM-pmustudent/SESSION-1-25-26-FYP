"""Signed opaque session cookies, persisted revocation and per-session CSRF."""
from http.cookies import SimpleCookie, CookieError
from pathlib import Path
import hashlib
import hmac
import json
import os
import secrets


class Auth:
    cookie_name = "awarelink_session"

    def __init__(self, settings, store):
        self.settings, self.store = settings, store
        secret_path = settings.data_dir / ".secret"
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        if settings.secret:
            self.secret = settings.secret.encode("utf-8")
        else:
            try:
                with secret_path.open("x", encoding="ascii") as stream:
                    stream.write(secrets.token_hex(32))
                os.chmod(secret_path, 0o600)
            except FileExistsError:
                pass
            self.secret = secret_path.read_bytes().strip()
        if len(self.secret) < 32:
            raise ValueError("AWARELINK_SECRET must contain at least 32 bytes.")
        self.credentials_path = settings.data_dir / "admin.json"
        self.credentials = None
        if settings.admin_password:
            self.credentials = self._make_credentials(settings.admin_username, settings.admin_password)
        elif self.credentials_path.exists():
            self.credentials = json.loads(self.credentials_path.read_text(encoding="utf-8"))

    @staticmethod
    def _make_credentials(username, password):
        if not username or len(password) < 12:
            raise ValueError("Choose an admin username and a password of at least 12 characters.")
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 240_000).hex()
        return {"username": username, "salt": salt, "digest": digest, "iterations": 240_000}

    def configure_admin(self, username, password):
        self.credentials = self._make_credentials(username, password)
        self.credentials_path.write_text(json.dumps(self.credentials), encoding="utf-8")
        os.chmod(self.credentials_path, 0o600)

    def _signature(self, value):
        return hmac.new(self.secret, value.encode("ascii"), hashlib.sha256).hexdigest()

    def resolve(self, environ):
        session = None
        raw_cookie = environ.get("HTTP_COOKIE", "")
        if len(raw_cookie) <= 4096:
            try:
                cookies = SimpleCookie(raw_cookie)
                value = cookies[self.cookie_name].value
                session_id, signature = value.split(".", 1)
                if signature.isascii() and len(signature) == 64 and hmac.compare_digest(signature, self._signature(session_id)):
                    session = self.store.get_session(session_id)
            except (KeyError, ValueError, UnicodeError, CookieError):
                pass
        if session:
            return session, None
        session = self.store.create_session()
        return session, self.cookie(session)

    def cookie(self, session):
        cookie = SimpleCookie()
        cookie[self.cookie_name] = session["id"] + "." + self._signature(session["id"])
        morsel = cookie[self.cookie_name]
        morsel["path"] = "/"
        morsel["httponly"] = True
        morsel["samesite"] = "Strict"
        morsel["max-age"] = 21600 if session["admin"] else 30 * 86400
        if self.settings.secure_cookie:
            morsel["secure"] = True
        return morsel.OutputString()

    def csrf_token(self, session):
        return self._signature("csrf:" + session["id"])

    def csrf_valid(self, session, token):
        return isinstance(token, str) and token.isascii() and len(token) == 64 and hmac.compare_digest(token, self.csrf_token(session))

    def login(self, session, username, password):
        if not self.credentials:
            return None
        stored = self.credentials
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(stored["salt"]), stored["iterations"]).hex()
        good_password = hmac.compare_digest(digest, stored["digest"])
        good_username = hmac.compare_digest(username.encode(), stored["username"].encode())
        if not good_username or not good_password:
            return None
        new_session = self.store.create_session(owner=session["owner"], admin=True, duration=21600)
        self.store.revoke_session(session["id"])
        return new_session

    def logout(self, session):
        self.store.revoke_session(session["id"])
        return self.store.create_session(owner=session["owner"])
