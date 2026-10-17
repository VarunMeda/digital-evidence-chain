from __future__ import annotations
import hashlib
import json
import os
import sys
ROOT = os.path.realpath(os.environ.get("EVIDENCE_STORAGE_ROOT", os.path.join(os.path.dirname(__file__), "..", "backend", "evidence-storage")))
def main() -> int:
    try:
        payload = json.load(sys.stdin); candidate = os.path.realpath(payload["path"])
        if os.path.commonpath([ROOT, candidate]) != ROOT: raise ValueError("path is outside configured evidence storage")
        digest = hashlib.sha256()
        with open(candidate, "rb") as handle:
            while chunk := handle.read(1024 * 1024): digest.update(chunk)
        print(digest.hexdigest()); return 0
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr); return 1
if __name__ == "__main__": raise SystemExit(main())
