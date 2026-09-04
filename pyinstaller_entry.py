"""Frozen-app entry point (PyInstaller).

Runs the local launcher, which binds the backend to a free loopback port, opens
the browser at a one-time bootstrap URL, and serves the bundled SPA.
"""

from reconscope.launcher import main

if __name__ == "__main__":
    main()
