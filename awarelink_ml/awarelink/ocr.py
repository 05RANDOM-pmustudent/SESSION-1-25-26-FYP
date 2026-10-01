"""Local image validation and OCR. Never uploads images to a third party."""
from pathlib import Path
from tempfile import TemporaryDirectory
import io
import os
import shutil
import subprocess
import warnings

from PIL import Image, ImageOps


class LocalOCR:
    def __init__(self, command=None):
        candidates = [command, shutil.which("tesseract")]
        if os.name == "nt":
            candidates += [str(Path(os.getenv("ProgramFiles", "C:/Program Files")) / "Tesseract-OCR" / "tesseract.exe")]
        self.command = next((value for value in candidates if value and Path(value).is_file()), None)
        self.available = bool(self.command)
        if self.command:
            try:
                languages = subprocess.run([self.command, "--list-langs"], capture_output=True, text=True, timeout=3, check=True)
                self.available = "eng" in languages.stdout.splitlines()
            except (OSError, subprocess.SubprocessError):
                self.available = False

    @staticmethod
    def validate(data):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(io.BytesIO(data)) as image:
                    if image.format not in ("PNG", "JPEG", "WEBP", "BMP") or getattr(image, "n_frames", 1) != 1:
                        raise ValueError("Use a single PNG, JPEG, WebP or BMP screenshot.")
                    if image.width * image.height > 12_000_000 or min(image.size) < 24:
                        raise ValueError("Screenshot dimensions are outside the supported range.")
                    image.verify()
        except (OSError, Image.DecompressionBombError, Image.DecompressionBombWarning) as error:
            raise ValueError("The screenshot is invalid or too large.") from error

    def extract(self, data):
        if not self.available:
            raise ValueError("Local OCR is unavailable. Install Tesseract with its English language data.")
        self.validate(data)
        with TemporaryDirectory(prefix="awarelink-ocr-") as directory:
            path = Path(directory) / "input.png"
            with Image.open(io.BytesIO(data)) as image:
                image = ImageOps.autocontrast(ImageOps.exif_transpose(image).convert("L"))
                image.thumbnail((2000, 2000), Image.Resampling.LANCZOS)
                image.save(path)
            env = os.environ.copy()
            env["OMP_THREAD_LIMIT"] = "1"
            try:
                completed = subprocess.run([self.command, str(path), "stdout", "-l", "eng", "--psm", "6"],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=12, check=True, env=env)
            except subprocess.TimeoutExpired as error:
                raise ValueError("Screenshot text extraction timed out. Use a smaller, clearer image.") from error
            except (OSError, subprocess.CalledProcessError) as error:
                raise ValueError("Screenshot text could not be extracted.") from error
            text = completed.stdout.strip()[:20_000]
            if len(text) < 10:
                raise ValueError("Too little readable text was found. Use a clear screenshot with text.")
            return text
