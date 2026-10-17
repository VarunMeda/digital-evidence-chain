import hashlib, json, os, subprocess, sys, tempfile, unittest
ROOT = os.path.dirname(__file__)
class HashFileTests(unittest.TestCase):
    def test_known_vector(self):
        with tempfile.TemporaryDirectory() as storage:
            path = os.path.join(storage, "sample.bin")
            with open(path, "wb") as handle: handle.write(b"digital evidence")
            env = os.environ.copy(); env["EVIDENCE_STORAGE_ROOT"] = storage
            result = subprocess.run([sys.executable, os.path.join(ROOT, "hash_file.py")], input=json.dumps({"path": path}), text=True, capture_output=True, env=env)
            self.assertEqual(result.returncode, 0); self.assertEqual(result.stdout.strip(), hashlib.sha256(b"digital evidence").hexdigest())
    def test_rejects_outside_path(self):
        with tempfile.TemporaryDirectory() as storage, tempfile.NamedTemporaryFile() as outside:
            env = os.environ.copy(); env["EVIDENCE_STORAGE_ROOT"] = storage
            result = subprocess.run([sys.executable, os.path.join(ROOT, "hash_file.py")], input=json.dumps({"path": outside.name}), text=True, capture_output=True, env=env)
            self.assertNotEqual(result.returncode, 0)
if __name__ == "__main__": unittest.main()
