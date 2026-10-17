"""Windows privacy checks for the application's saved account session."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from remote222.client import ClientError
from remote222.session import child_options, protect_private_state, verify_private_state


@unittest.skipUnless(os.name == "nt", "Requires actual Windows ACLs")
class WindowsAccountPermissionsTests(unittest.TestCase):
    def test_auth_folder_removes_explicit_foreign_grants_and_files_inherit_private_acl(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth"
            protect_private_state(path)
            verify_private_state(path)
            subprocess.run(["icacls.exe", str(path), "/grant", "*S-1-1-0:(OI)(CI)R"],
                           capture_output=True, check=True, timeout=10, **child_options())
            with self.assertRaises(ClientError):
                verify_private_state(path)
            protect_private_state(path)
            verify_private_state(path)
            profile = path / "worker.json"
            profile.write_text("{}", encoding="utf-8")
            verify_private_state(profile)
            subprocess.run(["icacls.exe", str(profile), "/grant", "*S-1-1-0:R"],
                           capture_output=True, check=True, timeout=10, **child_options())
            with self.assertRaises(ClientError):
                verify_private_state(profile)


if __name__ == "__main__":
    unittest.main()
