"""OCR engines for screenshot evidence.

The ingestion pipeline depends only on the :class:`OCREngine` protocol, so a
cloud OCR service can be swapped in without touching the rest of the module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

IMAGE_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
    b"BM": "image/bmp",
    b"II*\x00": "image/tiff",
    b"MM\x00*": "image/tiff",
}


def sniff_image_mime(data: bytes) -> str | None:
    """Identify an image by its magic bytes rather than trusting file extensions."""
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    for signature, mime in IMAGE_SIGNATURES.items():
        if data.startswith(signature):
            return mime
    return None


@dataclass
class OCRResult:
    text: str
    engine: str
    confidence: float | None = None
    details: dict = field(default_factory=dict)


class OCRUnavailableError(RuntimeError):
    """Raised when no OCR backend is installed or it failed to run."""


class OCREngine(Protocol):
    name: str

    def extract_text(self, image_bytes: bytes) -> OCRResult: ...


class TesseractOCR:
    """OCR via Tesseract (``pip install pillow pytesseract`` plus the tesseract binary)."""

    name = "tesseract"

    def __init__(self, lang: str = "eng", upscale_below: int = 1000):
        self.lang = lang
        self.upscale_below = upscale_below

    def extract_text(self, image_bytes: bytes) -> OCRResult:
        try:
            import io

            import pytesseract
            from PIL import Image, ImageOps
        except ImportError as exc:
            raise OCRUnavailableError(
                "Tesseract OCR requires 'pillow' and 'pytesseract'"
            ) from exc

        try:
            image = Image.open(io.BytesIO(image_bytes))
            width, height = image.size
            # Chat screenshots are often small and dark-themed; grayscale,
            # autocontrast and upscaling markedly improve Tesseract accuracy.
            image = ImageOps.autocontrast(ImageOps.grayscale(image))
            if width < self.upscale_below:
                factor = self.upscale_below / width
                image = image.resize((int(width * factor), int(height * factor)))

            data = pytesseract.image_to_data(
                image, lang=self.lang, output_type=pytesseract.Output.DICT
            )
        except pytesseract.TesseractNotFoundError as exc:
            raise OCRUnavailableError("tesseract binary not found on PATH") from exc

        lines: dict[tuple, list[str]] = {}
        confidences = []
        for i, word in enumerate(data["text"]):
            if not word.strip():
                continue
            key = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
            lines.setdefault(key, []).append(word)
            conf = float(data["conf"][i])
            if conf >= 0:
                confidences.append(conf)

        text = "\n".join(" ".join(words) for _, words in sorted(lines.items()))
        confidence = round(sum(confidences) / len(confidences) / 100, 3) if confidences else None
        return OCRResult(
            text=text,
            engine=self.name,
            confidence=confidence,
            details={"image_size": [width, height], "lang": self.lang},
        )


def default_engine() -> OCREngine:
    return TesseractOCR()
