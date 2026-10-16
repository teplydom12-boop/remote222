"""PyInstaller entry point; self-test is used by the Windows build job."""

import sys

if "--self-test" in sys.argv:
    from remote222.selftest import main
else:
    from remote222.desktop_app import main

main()
