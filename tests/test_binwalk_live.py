"""Optional genuine SquashFS/Binwalk test. Never runs without explicit opt-in."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"backend"))
from analysis import analyse

@unittest.skipUnless(os.environ.get("FIRMGUARD_RUN_BINWALK_TEST")=="1" and os.environ.get("FIRMGUARD_BINWALK_IMAGE"), "requires optional local Docker Binwalk image and explicit opt-in")
class LiveBinwalkTest(unittest.TestCase):
    def test_squashfs_extraction(self):
        with tempfile.TemporaryDirectory(prefix="firmguard-squashfs-") as directory:
            root=Path(directory);(root/"device.conf").write_text("password=DUMMY_CONTAINER_TEST\n",encoding="utf-8")
            command=["docker","run","--rm","--pull=never","--network=none","--read-only","--cap-drop=ALL",
              "--security-opt=no-new-privileges","--user=65534:65534","--memory=256m","--pids-limit=32",
              "--tmpfs","/work:rw,noexec,nosuid,nodev,size=16m,mode=1777",
              "--mount",f"type=bind,source={root},target=/fixture,readonly",
              "--entrypoint","sh",os.environ["FIRMGUARD_BINWALK_IMAGE"],"-c",
              "mksquashfs /fixture /work/test.squashfs -noappend -comp gzip -processors 1 >/dev/null && cat /work/test.squashfs"]
            image=subprocess.run(command,capture_output=True,timeout=60,check=True).stdout
            self.assertTrue(image.startswith(b"hsqs"))
            result=analyse(image,"test.squashfs",use_binwalk=True)
            self.assertEqual(result["extraction"]["method"],"binwalk-docker")
            self.assertTrue(any(f["rule_id"]=="CRED-001" for f in result["findings"]))

if __name__=="__main__":unittest.main()
