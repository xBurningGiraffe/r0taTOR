#!/usr/bin/env python3
"""
tor-newip.py
Ask the local Tor control port (127.0.0.1:9051) to build a new circuit.

• Uses cookie authentication, so no password is required.
• Exits 0 on success; non-zero on failure (handy for systemd).
"""

import pathlib
import socket
import sys
import time

COOKIE = pathlib.Path("/run/tor/control.authcookie")  # default location
HOST, PORT = "127.0.0.1", 9051


def _ctl(sock: socket.socket, line: str) -> bytes:
    """Send a single control-port line, return Tor’s first reply line."""
    sock.sendall(line.encode() + b"\r\n")
    return sock.recv(1024)


def main() -> int:
    if not COOKIE.exists() or COOKIE.stat().st_size != 32:
        print("tor-newip: control_authcookie missing or wrong size", file=sys.stderr)
        return 2

    cookie_hex = COOKIE.read_bytes().hex()

    try:
        with socket.create_connection((HOST, PORT), timeout=4.0) as s:
            if not _ctl(s, f"AUTHENTICATE {cookie_hex}").startswith(b"250"):
                print("tor-newip: authentication failed", file=sys.stderr)
                return 3
            if not _ctl(s, "SIGNAL NEWNYM").startswith(b"250"):
                print("tor-newip: NEWNYM command failed", file=sys.stderr)
                return 4
            _ctl(s, "QUIT")
    except OSError as e:
        print(f"tor-newip: {e}", file=sys.stderr)
        return 5

    print(f"[{time.strftime('%F %T')}]  New Tor circuit requested.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
