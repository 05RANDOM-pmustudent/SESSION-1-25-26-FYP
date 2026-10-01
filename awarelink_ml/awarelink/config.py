from dataclasses import dataclass, field
from pathlib import Path
import os


@dataclass
class Settings:
    base_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent)
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("AWARELINK_DATA_DIR", "data")))
    host: str = "127.0.0.1"
    port: int = 8765
    workers: int = 4
    queue_size: int = 8
    cache_size: int = 256
    cache_ttl: float = 600
    max_body_bytes: int = 2_500_000
    max_image_bytes: int = 2_000_000
    max_text_chars: int = 12_000
    max_url_chars: int = 2048
    admin_username: str = "admin"
    admin_password: str | None = None
    secret: str | None = None
    secure_cookie: bool = False
    ocr_command: str | None = None
    request_limit: int = 120
    request_window: float = 60

    def __post_init__(self):
        self.base_dir = Path(self.base_dir).resolve()
        self.data_dir = Path(self.data_dir).resolve()
        if not 1 <= self.workers <= 32 or not 0 <= self.queue_size <= 256:
            raise ValueError("Workers must be 1–32 and queue size 0–256.")
        if self.cache_size < 1 or self.cache_ttl < 0:
            raise ValueError("Invalid cache limits.")
        if min(self.max_body_bytes, self.max_image_bytes, self.max_text_chars, self.max_url_chars) < 1:
            raise ValueError("Input limits must be positive.")
        if self.max_image_bytes > self.max_body_bytes or self.request_limit < 1:
            raise ValueError("Invalid image or request limit.")

    @classmethod
    def from_env(cls):
        return cls(
            data_dir=Path(os.getenv("AWARELINK_DATA_DIR", "data")),
            host=os.getenv("AWARELINK_HOST", "127.0.0.1"),
            port=int(os.getenv("PORT", os.getenv("AWARELINK_PORT", "8765"))),
            workers=int(os.getenv("AWARELINK_WORKERS", "4")),
            queue_size=int(os.getenv("AWARELINK_QUEUE_SIZE", "8")),
            admin_username=os.getenv("AWARELINK_ADMIN_USERNAME", "admin"),
            admin_password=os.getenv("AWARELINK_ADMIN_PASSWORD"),
            secret=os.getenv("AWARELINK_SECRET"),
            secure_cookie=os.getenv("AWARELINK_SECURE_COOKIE", "0") == "1",
            ocr_command=os.getenv("TESSERACT_CMD"),
        )
