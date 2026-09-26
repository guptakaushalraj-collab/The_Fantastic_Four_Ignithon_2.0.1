"""PDF evidence: bank statements, e-mail printouts and scanned documents.

Pages with a text layer are read directly. Scanned pages (images only) are
rendered and passed to OCR. Needs ``pdfplumber`` (``pip install pdfplumber``).
"""

from __future__ import annotations

import io
from dataclasses import dataclass

PDF_MIME = "application/pdf"
# A page with less text than this is treated as a scan.
MIN_TEXT_CHARS = 40


class PDFUnavailableError(RuntimeError):
    """Raised when PDF support is not installed or the file cannot be read."""


@dataclass
class PDFPage:
    number: int
    text: str | None          # the text layer, if the page has one
    image_png: bytes | None   # the rendered page, for OCR, if it has no text layer


def is_pdf(data: bytes) -> bool:
    return data[:5] == b"%PDF-"


def read_pdf(data: bytes, resolution: int = 300) -> list[PDFPage]:
    try:
        import pdfplumber
    except ImportError as exc:
        raise PDFUnavailableError(
            "PDF support requires 'pdfplumber' (pip install -r requirements.txt)") from exc
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:  # a broken 'cryptography' install panics on import
        raise PDFUnavailableError(
            f"pdfplumber failed to load ({type(exc).__name__}: {exc}); "
            "try: pip install --upgrade cffi cryptography") from exc
    try:
        pages = []
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            for number, page in enumerate(pdf.pages, start=1):
                text = page.extract_text() or ""
                if len(text.strip()) >= MIN_TEXT_CHARS:
                    pages.append(PDFPage(number, text, None))
                    continue
                buffer = io.BytesIO()
                page.to_image(resolution=resolution).original.save(buffer, format="PNG")
                pages.append(PDFPage(number, None, buffer.getvalue()))
        return pages
    except Exception as exc:  # pdfplumber raises many parser-specific errors
        raise PDFUnavailableError(f"could not read PDF: {exc}") from exc
