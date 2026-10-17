import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.dirname(__file__)
SCRIPT = os.path.join(ROOT, "extract_metadata.py")


def run_extractor(storage, path, name):
    env = os.environ.copy()
    env["EVIDENCE_STORAGE_ROOT"] = storage
    result = subprocess.run([sys.executable, SCRIPT], input=json.dumps({"path": path, "original_filename": name}), text=True, capture_output=True, env=env)
    return result, json.loads(result.stdout) if result.stdout else None


class MetadataExtractionTests(unittest.TestCase):
    def test_json_structural_metadata_and_original_bytes(self):
        with tempfile.TemporaryDirectory() as storage:
            path = os.path.join(storage, "sample.json")
            data = b'{"case_id": 7, "items": [1, 2]}'
            with open(path, "wb") as handle:
                handle.write(data)
            original_hash = hashlib.sha256(data).hexdigest()
            result, output = run_extractor(storage, path, "sample.json")
            self.assertEqual(result.returncode, 0)
            self.assertEqual(output["artifact_type"], "STRUCTURAL_VALIDATION")
            self.assertEqual(output["fields"]["key_count"], 2)
            with open(path, "rb") as handle:
                self.assertEqual(hashlib.sha256(handle.read()).hexdigest(), original_hash)

    def test_docx_and_image_metadata(self):
        with tempfile.TemporaryDirectory() as storage:
            docx = os.path.join(storage, "sample.docx")
            with zipfile.ZipFile(docx, "w") as archive:
                archive.writestr("word/document.xml", b"<w:document><w:body><w:p /></w:body></w:document>")
            result, output = run_extractor(storage, docx, "sample.docx")
            self.assertEqual(result.returncode, 0)
            self.assertEqual(output["fields"]["format"], "DOCX")

            try:
                from PIL import Image
            except ImportError:
                self.skipTest("Pillow is unavailable")
            image = os.path.join(storage, "sample.png")
            Image.new("RGB", (3, 2), "white").save(image)
            result, output = run_extractor(storage, image, "sample.png")
            self.assertEqual(result.returncode, 0)
            self.assertEqual(output["fields"]["width"], 3)
            self.assertEqual(output["fields"]["height"], 2)

    def test_malformed_and_unsupported_inputs_fail_safely(self):
        with tempfile.TemporaryDirectory() as storage:
            malformed = os.path.join(storage, "bad.json")
            with open(malformed, "wb") as handle:
                handle.write(b"not json")
            result, _ = run_extractor(storage, malformed, "bad.json")
            self.assertNotEqual(result.returncode, 0)
            unsupported = os.path.join(storage, "video.mp4")
            with open(unsupported, "wb") as handle:
                handle.write(b"not a video")
            result, _ = run_extractor(storage, unsupported, "video.mp4")
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
