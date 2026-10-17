from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
import zipfile
from pathlib import Path
from typing import Any, Callable
from xml.etree import ElementTree

try:
    from PIL import Image
except ImportError:  # The service remains safe; image extraction reports a dependency error.
    Image = None

ROOT = Path(os.path.realpath(os.environ.get("EVIDENCE_STORAGE_ROOT", Path(__file__).parent.parent / "backend" / "evidence-storage")))
PARSER_NAME = "python-forensic-metadata"
PARSER_VERSION = "1.0.0"
MAX_READ_BYTES = 8 * 1024 * 1024


def ensure_private_file(path_value: Any, max_bytes: int) -> Path:
    if not isinstance(path_value, str):
        raise ValueError("path is required")
    candidate = Path(os.path.realpath(path_value))
    if os.path.commonpath([str(ROOT), str(candidate)]) != str(ROOT):
        raise ValueError("path is outside configured evidence storage")
    if not candidate.is_file():
        raise ValueError("evidence file is not available")
    if candidate.stat().st_size > max_bytes:
        raise ValueError("evidence file exceeds the analysis size limit")
    return candidate


def image_metadata(path: Path) -> dict[str, Any]:
    if Image is None:
        raise ValueError("image metadata parser dependency is unavailable")
    with Image.open(path) as image:
        image.verify()
    with Image.open(path) as image:
        fields: dict[str, Any] = {"format": image.format, "width": image.width, "height": image.height, "mode": image.mode}
        if getattr(image, "n_frames", 1) > 1:
            fields["frames"] = image.n_frames
        dpi = image.info.get("dpi")
        if isinstance(dpi, tuple) and len(dpi) == 2 and all(isinstance(value, (int, float)) for value in dpi):
            fields["dpi"] = [dpi[0], dpi[1]]
        fields["metadata_keys"] = sorted(str(key) for key in image.info.keys() if key not in {"exif", "icc_profile"})[:32]
        return fields


def pdf_metadata(path: Path) -> dict[str, Any]:
    data = path.read_bytes()[:MAX_READ_BYTES]
    if not data.startswith(b"%PDF-"):
        raise ValueError("file is not a valid PDF header")
    return {"format": "PDF", "header": data[:8].decode("ascii", "replace"), "page_objects": len(re.findall(rb"/Type\s*/Page(?:\s|/|>)", data)), "has_xref": b"xref" in data, "has_trailer": b"trailer" in data, "sampled_bytes": len(data)}


def text_encoding(path: Path) -> tuple[str, int]:
    raw = path.read_bytes()[:MAX_READ_BYTES]
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        encoding = "utf-16"
    elif raw.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"
    else:
        encoding = "utf-8"
    try:
        text = raw.decode(encoding)
    except UnicodeDecodeError as error:
        raise ValueError("text is not valid UTF-8 or UTF-16") from error
    return encoding, text.count("\n") + (1 if text and not text.endswith("\n") else 0)


def text_metadata(path: Path, extension: str) -> dict[str, Any]:
    encoding, lines = text_encoding(path)
    fields: dict[str, Any] = {"format": extension.lstrip(".").upper(), "encoding": encoding, "line_count_sample": lines, "sampled_bytes": min(path.stat().st_size, MAX_READ_BYTES)}
    if extension == ".csv":
        sample = path.read_bytes()[:MAX_READ_BYTES].decode(encoding)
        try:
            dialect = csv.Sniffer().sniff(sample[:8192])
            fields["delimiter"] = dialect.delimiter
        except csv.Error:
            fields["delimiter"] = ","
        fields["column_count_sample"] = len(next(csv.reader(io.StringIO(sample)), [])) if sample else 0
    return fields


def json_metadata(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_READ_BYTES:
        raise ValueError("JSON input exceeds the parser limit")
    value = json.loads(raw.decode("utf-8"))
    if isinstance(value, dict):
        return {"format": "JSON", "top_level": "object", "key_count": len(value), "keys": sorted(str(key) for key in value.keys())[:64]}
    if isinstance(value, list):
        return {"format": "JSON", "top_level": "array", "item_count": len(value)}
    return {"format": "JSON", "top_level": type(value).__name__}


def xml_metadata(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_READ_BYTES:
        raise ValueError("XML input exceeds the parser limit")
    root = ElementTree.parse(path).getroot()
    elements = sum(1 for _ in root.iter())
    attributes = sum(len(node.attrib) for node in root.iter())
    return {"format": "XML", "root_tag": root.tag, "element_count": elements, "attribute_count": attributes}


def docx_metadata(path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise ValueError("DOCX archive is corrupt")
        total_uncompressed = sum(info.file_size for info in archive.infolist())
        if total_uncompressed > MAX_READ_BYTES:
            raise ValueError("DOCX uncompressed content exceeds the parser limit")
        document = archive.read("word/document.xml")
        paragraphs = document.count(b"<w:p")
        tables = document.count(b"<w:tbl")
        fields: dict[str, Any] = {"format": "DOCX", "paragraph_count": paragraphs, "table_count": tables}
        if "docProps/core.xml" in archive.namelist():
            core = ElementTree.fromstring(archive.read("docProps/core.xml"))
            for node in core.iter():
                if node.tag.rsplit("}", 1)[-1] in {"title", "creator", "subject"} and node.text:
                    fields[node.tag.rsplit("}", 1)[-1]] = node.text[:256]
        return fields


def extract(path: Path, original_filename: str) -> dict[str, Any]:
    extension = Path(original_filename).suffix.lower()
    image_extensions = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp"}
    if extension in image_extensions:
        return {"artifact_type": "METADATA_EXTRACTION", "fields": image_metadata(path)}
    if extension == ".pdf":
        return {"artifact_type": "STRUCTURAL_VALIDATION", "fields": pdf_metadata(path)}
    if extension in {".txt", ".csv", ".log"}:
        return {"artifact_type": "METADATA_EXTRACTION", "fields": text_metadata(path, extension)}
    if extension == ".json":
        return {"artifact_type": "STRUCTURAL_VALIDATION", "fields": json_metadata(path)}
    if extension == ".xml":
        return {"artifact_type": "STRUCTURAL_VALIDATION", "fields": xml_metadata(path)}
    if extension == ".docx":
        return {"artifact_type": "METADATA_EXTRACTION", "fields": docx_metadata(path)}
    raise ValueError("No safe metadata parser is implemented for this evidence format")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        path = ensure_private_file(payload.get("path"), int(payload.get("max_bytes", 512 * 1024 * 1024)))
        original_filename = str(payload.get("original_filename") or path.name)
        result = extract(path, original_filename)
        result.update({"extraction_status": "COMPLETED", "parser": {"name": PARSER_NAME, "version": PARSER_VERSION}, "provenance": {"source": "forensic-service", "method": "safe-metadata-extraction"}})
        output = json.dumps(result, separators=(",", ":"))
        if len(output.encode()) > int(payload.get("max_output_bytes", 256 * 1024)):
            raise ValueError("extraction output exceeds the configured limit")
        print(output)
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, zipfile.BadZipFile, ElementTree.ParseError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
