"""OCR engines for screenshot evidence.

The ingestion pipeline depends only on the :class:`OCREngine` protocol, so a
cloud OCR service can be swapped in without touching the rest of the module.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass, field
from typing import Protocol

# Where the Windows installers put Tesseract, for when it isn't on PATH.
_WINDOWS_TESSERACT = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
]
TESSERACT_HELP = (
    "Tesseract OCR is not installed or not on PATH. Install it (Ubuntu: sudo apt install "
    "tesseract-ocr; macOS: brew install tesseract; Windows: the UB Mannheim installer), "
    "or set TESSERACT_CMD to the full path of tesseract.exe"
)


def find_tesseract() -> str | None:
    """Path of the tesseract program: $TESSERACT_CMD, then PATH, then the Windows defaults."""
    if cmd := os.environ.get("TESSERACT_CMD"):
        return cmd if os.path.isfile(cmd) else None
    if found := shutil.which("tesseract"):
        return found
    if sys.platform == "win32":
        return next((p for p in _WINDOWS_TESSERACT if os.path.isfile(p)), None)
    return None

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

    def __init__(self, lang: str = "eng", upscale_below: int = 1000, psm: int | None = None,
                 remove_highlights: bool = False):
        """``psm`` is Tesseract's page segmentation mode; 6 ("one block of text") keeps each
        printed table row on one line, which statements need. ``remove_highlights`` whitens
        highlighter marks, which otherwise hide the text under them."""
        self.lang = lang
        self.upscale_below = upscale_below
        self.psm = psm
        self.remove_highlights = remove_highlights

    def extract_text(self, image_bytes: bytes) -> OCRResult:
        try:
            import io

            import pytesseract
            from PIL import Image, ImageChops, ImageOps
        except ImportError as exc:
            raise OCRUnavailableError(
                "Tesseract OCR requires 'pillow' and 'pytesseract' (pip install -r requirements.txt)"
            ) from exc
        if not (cmd := find_tesseract()):
            raise OCRUnavailableError(TESSERACT_HELP)
        pytesseract.pytesseract.tesseract_cmd = cmd

        try:
            image = Image.open(io.BytesIO(image_bytes))
            width, height = image.size
            # Chat screenshots are often small and dark-themed; grayscale,
            # autocontrast and upscaling markedly improve Tesseract accuracy.
            if self.remove_highlights:
                # Brightest channel: coloured highlighter turns white, dark ink stays dark.
                r, g, b = image.convert("RGB").split()
                image = ImageChops.lighter(ImageChops.lighter(r, g), b)
            image = ImageOps.autocontrast(ImageOps.grayscale(image))
            if width < self.upscale_below:
                factor = self.upscale_below / width
                image = image.resize((int(width * factor), int(height * factor)))

            data = pytesseract.image_to_data(
                image, lang=self.lang, output_type=pytesseract.Output.DICT,
                config=f"--psm {self.psm}" if self.psm else "",
            )
        except pytesseract.TesseractNotFoundError as exc:
            raise OCRUnavailableError(TESSERACT_HELP) from exc

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
            details={"image_size": [width, height], "lang": self.lang,
                     **({"psm": self.psm} if self.psm else {}),
                     **({"remove_highlights": True} if self.remove_highlights else {})},
        )


def default_engine() -> OCREngine:
    return TesseractOCR()


def document_engines() -> list[OCREngine]:
    """OCR passes for scanned documents; the reading that parses best is kept."""
    return [TesseractOCR(psm=6), TesseractOCR(psm=6, remove_highlights=True)]
