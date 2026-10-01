from getpass import getpass
import argparse
import logging

from .app import create_app
from .config import Settings


def main():
    parser = argparse.ArgumentParser(description="Run AwareLink with local trained models.")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--setup-admin", action="store_true")
    args = parser.parse_args()
    settings = Settings.from_env()
    if args.host:
        settings.host = args.host
    if args.port:
        settings.port = args.port
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    application = create_app(settings)
    if args.setup_admin:
        try:
            username = input("Admin username [admin]: ").strip() or "admin"
            password = getpass("Password (at least 12 characters): ")
            confirmation = getpass("Repeat password: ")
            if password != confirmation:
                raise ValueError("Passwords did not match.")
            application.auth.configure_admin(username, password)
            print("Admin credentials saved as a salted password hash in the data directory.")
        finally:
            application.close()
        return
    import uvicorn
    from .transport import ASGIAdapter
    adapter = ASGIAdapter(application)
    print(f"AwareLink is available at http://{settings.host}:{settings.port}")
    print("Local OCR: " + ("ready" if application.ocr.available else "unavailable; install Tesseract for screenshots"))
    if not application.auth.credentials:
        print("Admin login is disabled. Run python -m awarelink --setup-admin to configure it.")
    try:
        trusted_proxies = __import__("os").getenv("AWARELINK_TRUSTED_PROXY_IPS", "")
        uvicorn.run(adapter, host=settings.host, port=settings.port, http="h11", loop="asyncio",
                    access_log=False, limit_concurrency=64, timeout_keep_alive=60,
                    proxy_headers=bool(trusted_proxies), forwarded_allow_ips=trusted_proxies,
                    timeout_graceful_shutdown=30)
    finally:
        adapter.close()


if __name__ == "__main__":
    main()
