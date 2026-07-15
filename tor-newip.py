#!/usr/bin/env python3
"""
tor-newip.py
Rotate the local Tor circuit, display the current Tor exit IP, or do both.

Uses cookie authentication for Tor's control port and the Python standard
library only. Exits 0 on success and non-zero on failure.
"""

import argparse
import ipaddress
import json
import pathlib
import socket
import ssl
import struct
import sys
import time

COOKIE = pathlib.Path("/run/tor/control.authcookie")
CONTROL_HOST, CONTROL_PORT = "127.0.0.1", 9051
SOCKS_HOST, SOCKS_PORT = "127.0.0.1", 9050
IP_CHECK_HOST = "check.torproject.org"
IP_CHECK_PATH = "/api/ip"


def _ctl(sock: socket.socket, line: str) -> bytes:
    """Send one Tor control-port command and return its first reply block."""
    sock.sendall(line.encode("ascii") + b"\r\n")
    return sock.recv(1024)


def request_new_circuit() -> int:
    """Authenticate to Tor's control port and request a new circuit."""
    if not COOKIE.exists() or COOKIE.stat().st_size != 32:
        print("tor-newip: control_authcookie missing or wrong size", file=sys.stderr)
        return 2

    cookie_hex = COOKIE.read_bytes().hex()

    try:
        with socket.create_connection((CONTROL_HOST, CONTROL_PORT), timeout=4.0) as sock:
            if not _ctl(sock, f"AUTHENTICATE {cookie_hex}").startswith(b"250"):
                print("tor-newip: authentication failed", file=sys.stderr)
                return 3
            if not _ctl(sock, "SIGNAL NEWNYM").startswith(b"250"):
                print("tor-newip: NEWNYM command failed", file=sys.stderr)
                return 4
            _ctl(sock, "QUIT")
    except OSError as exc:
        print(f"tor-newip: {exc}", file=sys.stderr)
        return 5

    print(f"[{time.strftime('%F %T')}] New Tor circuit requested.")
    return 0


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    """Receive exactly size bytes or raise an error."""
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("SOCKS proxy closed the connection unexpectedly")
        data.extend(chunk)
    return bytes(data)


def _open_socks5_connection(host: str, port: int) -> socket.socket:
    """Open a TCP connection to host:port through the local Tor SOCKS5 proxy."""
    sock = socket.create_connection((SOCKS_HOST, SOCKS_PORT), timeout=8.0)
    try:
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("Tor SOCKS proxy rejected unauthenticated SOCKS5")

        host_bytes = host.encode("idna")
        if len(host_bytes) > 255:
            raise ValueError("destination hostname is too long")

        request = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes
        request += struct.pack("!H", port)
        sock.sendall(request)

        version, reply, _, address_type = _recv_exact(sock, 4)
        if version != 5 or reply != 0:
            raise OSError(f"Tor SOCKS proxy connection failed with code {reply}")

        if address_type == 1:
            _recv_exact(sock, 4)
        elif address_type == 3:
            _recv_exact(sock, _recv_exact(sock, 1)[0])
        elif address_type == 4:
            _recv_exact(sock, 16)
        else:
            raise OSError(f"Tor SOCKS proxy returned unknown address type {address_type}")

        _recv_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


def get_tor_exit_ip() -> str:
    """Return the current Tor exit IP after verifying the request used Tor."""
    raw_sock = _open_socks5_connection(IP_CHECK_HOST, 443)
    context = ssl.create_default_context()

    try:
        with context.wrap_socket(raw_sock, server_hostname=IP_CHECK_HOST) as tls_sock:
            request = (
                f"GET {IP_CHECK_PATH} HTTP/1.1\r\n"
                f"Host: {IP_CHECK_HOST}\r\n"
                "User-Agent: r0taTOR/1.0\r\n"
                "Accept: application/json\r\n"
                "Connection: close\r\n\r\n"
            )
            tls_sock.sendall(request.encode("ascii"))

            response = bytearray()
            while True:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
    except Exception:
        raw_sock.close()
        raise

    headers, separator, body = bytes(response).partition(b"\r\n\r\n")
    if not separator:
        raise OSError("invalid HTTP response from Tor Project IP service")

    status_line = headers.split(b"\r\n", 1)[0]
    if b" 200 " not in status_line:
        raise OSError(f"Tor Project IP service returned {status_line.decode(errors='replace')}")

    payload = json.loads(body.decode("utf-8"))
    ip_text = str(payload.get("IP", "")).strip()
    is_tor = payload.get("IsTor")

    try:
        ipaddress.ip_address(ip_text)
    except ValueError as exc:
        raise OSError("Tor Project IP service returned an invalid IP address") from exc

    if is_tor is not True:
        raise OSError("IP check did not confirm that the connection used Tor")

    return ip_text


def show_current_ip() -> int:
    """Print the current verified Tor exit IP."""
    try:
        print(f"Current Tor Exit IP: {get_tor_exit_ip()}")
        return 0
    except (OSError, ssl.SSLError, json.JSONDecodeError, ValueError) as exc:
        print(f"tor-newip: unable to determine Tor exit IP: {exc}", file=sys.stderr)
        return 6


def rotate_and_show(wait_seconds: float) -> int:
    """Rotate the circuit, wait briefly, and display the resulting exit IP."""
    try:
        old_ip = get_tor_exit_ip()
        print(f"Old IP: {old_ip}")
    except (OSError, ssl.SSLError, json.JSONDecodeError, ValueError) as exc:
        print(f"tor-newip: unable to determine current Tor exit IP: {exc}", file=sys.stderr)
        return 6

    result = request_new_circuit()
    if result != 0:
        return result

    print(f"Waiting {wait_seconds:g} seconds for a new circuit...")
    time.sleep(wait_seconds)

    try:
        new_ip = get_tor_exit_ip()
    except (OSError, ssl.SSLError, json.JSONDecodeError, ValueError) as exc:
        print(f"tor-newip: unable to determine new Tor exit IP: {exc}", file=sys.stderr)
        return 6

    print(f"New IP: {new_ip}")
    if new_ip == old_ip:
        print("Warning: Tor returned the same exit IP.", file=sys.stderr)
        return 7

    print("Circuit changed successfully.")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rotate the local Tor circuit or display its current exit IP."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "-i",
        "--ip",
        action="store_true",
        help="display the current verified Tor exit IP without rotating",
    )
    mode.add_argument(
        "-r",
        "--rotate-and-show",
        action="store_true",
        help="rotate the circuit and display the old and new exit IPs",
    )
    parser.add_argument(
        "--wait",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="seconds to wait before checking the new IP, default: 5",
    )
    args = parser.parse_args()

    if args.wait < 0:
        parser.error("--wait must be zero or greater")

    return args


def main() -> int:
    args = parse_args()

    if args.ip:
        return show_current_ip()
    if args.rotate_and_show:
        return rotate_and_show(args.wait)

    return request_new_circuit()


if __name__ == "__main__":
    sys.exit(main())
