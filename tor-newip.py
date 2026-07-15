#!/usr/bin/env python3
"""
tor-newip.py

Rotate the local Tor circuit, display the current Tor exit IP, or do both.

Uses cookie authentication for Tor's control port and the Python standard
library only. Exits 0 on success and non-zero on failure.

Compatible with Python 3.8 and later.
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
from typing import Callable, Dict, List, Tuple


COOKIE = pathlib.Path("/run/tor/control.authcookie")

CONTROL_HOST = "127.0.0.1"
CONTROL_PORT = 9051

SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 9050

NETWORK_TIMEOUT = 15.0


IP_ENDPOINTS: Tuple[Tuple[str, str, str], ...] = (
    ("api.ipify.org", "/?format=json", "json_ipify"),
    ("check.torproject.org", "/api/ip", "json_torproject"),
    ("icanhazip.com", "/", "plain"),
)


def _ctl(sock: socket.socket, line: str) -> bytes:
    """
    Send one Tor control-port command and return its first reply block.
    """
    sock.sendall(line.encode("ascii") + b"\r\n")
    return sock.recv(1024)


def request_new_circuit() -> int:
    """
    Authenticate to Tor's control port and request a new circuit.
    """
    if not COOKIE.exists() or COOKIE.stat().st_size != 32:
        print(
            "tor-newip: control_authcookie missing or wrong size",
            file=sys.stderr,
        )
        return 2

    cookie_hex = COOKIE.read_bytes().hex()

    try:
        with socket.create_connection(
            (CONTROL_HOST, CONTROL_PORT),
            timeout=4.0,
        ) as sock:
            authentication_reply = _ctl(
                sock,
                "AUTHENTICATE {}".format(cookie_hex),
            )

            if not authentication_reply.startswith(b"250"):
                print(
                    "tor-newip: authentication failed",
                    file=sys.stderr,
                )
                return 3

            newnym_reply = _ctl(sock, "SIGNAL NEWNYM")

            if not newnym_reply.startswith(b"250"):
                print(
                    "tor-newip: NEWNYM command failed",
                    file=sys.stderr,
                )
                return 4

            _ctl(sock, "QUIT")

    except OSError as exc:
        print(
            "tor-newip: {}".format(exc),
            file=sys.stderr,
        )
        return 5

    print(
        "[{}] New Tor circuit requested.".format(
            time.strftime("%F %T")
        )
    )

    return 0


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    """
    Receive exactly the requested number of bytes.

    Raises:
        OSError: If the connection closes before enough data is received.
    """
    data = bytearray()

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise OSError(
                "SOCKS proxy closed the connection unexpectedly"
            )

        data.extend(chunk)

    return bytes(data)


def _open_socks5_connection(
    host: str,
    port: int,
) -> socket.socket:
    """
    Open a TCP connection to host:port through the local Tor SOCKS5 proxy.
    """
    sock = socket.create_connection(
        (SOCKS_HOST, SOCKS_PORT),
        timeout=NETWORK_TIMEOUT,
    )

    try:
        sock.settimeout(NETWORK_TIMEOUT)

        # SOCKS5 greeting:
        # Version 5, one authentication method, no authentication.
        sock.sendall(b"\x05\x01\x00")

        greeting_reply = _recv_exact(sock, 2)

        if greeting_reply != b"\x05\x00":
            raise OSError(
                "Tor SOCKS proxy rejected unauthenticated SOCKS5"
            )

        # Pass the hostname to Tor instead of resolving it locally.
        host_bytes = host.encode("idna")

        if len(host_bytes) > 255:
            raise ValueError(
                "destination hostname is too long"
            )

        # SOCKS5 CONNECT request:
        # Version 5
        # Command 1, CONNECT
        # Reserved byte 0
        # Address type 3, domain name
        request = (
            b"\x05\x01\x00\x03"
            + bytes([len(host_bytes)])
            + host_bytes
            + struct.pack("!H", port)
        )

        sock.sendall(request)

        version, reply, _, address_type = _recv_exact(sock, 4)

        if version != 5:
            raise OSError(
                "Tor SOCKS proxy returned an invalid SOCKS version"
            )

        if reply != 0:
            raise OSError(
                "Tor SOCKS proxy connection failed with code {}".format(
                    reply
                )
            )

        # Consume the bound address returned by the SOCKS proxy.
        if address_type == 1:
            # IPv4
            _recv_exact(sock, 4)

        elif address_type == 3:
            # Domain name
            domain_length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, domain_length)

        elif address_type == 4:
            # IPv6
            _recv_exact(sock, 16)

        else:
            raise OSError(
                "Tor SOCKS proxy returned unknown address type {}".format(
                    address_type
                )
            )

        # Consume the two-byte bound port.
        _recv_exact(sock, 2)

        return sock

    except Exception:
        sock.close()
        raise


def _decode_chunked(body: bytes) -> bytes:
    """
    Decode an HTTP/1.1 chunked response body.
    """
    output = bytearray()
    remainder = body

    while True:
        line, separator, remainder = remainder.partition(b"\r\n")

        if not separator:
            raise OSError(
                "invalid chunked HTTP response"
            )

        try:
            chunk_size_text = line.split(b";", 1)[0]
            chunk_size = int(chunk_size_text, 16)

        except ValueError as exc:
            raise OSError(
                "invalid HTTP chunk size"
            ) from exc

        if chunk_size == 0:
            return bytes(output)

        if len(remainder) < chunk_size + 2:
            raise OSError(
                "truncated chunked HTTP response"
            )

        output.extend(remainder[:chunk_size])

        # Skip the chunk data and its trailing CRLF.
        remainder = remainder[chunk_size + 2:]


def _https_get_through_tor(
    host: str,
    path: str,
) -> bytes:
    """
    Perform an HTTPS GET through Tor and return the decoded response body.
    """
    raw_sock = _open_socks5_connection(host, 443)
    context = ssl.create_default_context()

    try:
        with context.wrap_socket(
            raw_sock,
            server_hostname=host,
        ) as tls_sock:
            tls_sock.settimeout(NETWORK_TIMEOUT)

            request = (
                "GET {} HTTP/1.1\r\n"
                "Host: {}\r\n"
                "User-Agent: r0taTOR/1.1\r\n"
                "Accept: application/json,text/plain\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).format(path, host)

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

    headers, separator, body = bytes(response).partition(
        b"\r\n\r\n"
    )

    if not separator:
        raise OSError(
            "invalid HTTP response"
        )

    status_line = headers.split(b"\r\n", 1)[0]

    if b" 200 " not in status_line:
        raise OSError(
            "service returned {}".format(
                status_line.decode(
                    "utf-8",
                    errors="replace",
                )
            )
        )

    lower_headers = headers.lower()

    if b"transfer-encoding: chunked" in lower_headers:
        body = _decode_chunked(body)

    return body


def _parse_ipify(body: bytes) -> str:
    """
    Parse the JSON response returned by api.ipify.org.
    """
    payload = json.loads(body.decode("utf-8"))
    return str(payload.get("ip", "")).strip()


def _parse_torproject(body: bytes) -> str:
    """
    Parse the JSON response returned by check.torproject.org.
    """
    payload = json.loads(body.decode("utf-8"))

    if payload.get("IsTor") is not True:
        raise OSError(
            "Tor Project did not confirm that the request used Tor"
        )

    return str(payload.get("IP", "")).strip()


def _parse_plain(body: bytes) -> str:
    """
    Parse an IP service that returns a plain-text address.
    """
    return body.decode("utf-8").strip()


PARSERS: Dict[str, Callable[[bytes], str]] = {
    "json_ipify": _parse_ipify,
    "json_torproject": _parse_torproject,
    "plain": _parse_plain,
}


def get_tor_exit_ip() -> str:
    """
    Return the current exit IP observed through the local Tor SOCKS proxy.

    Multiple IP services are tried so that one unavailable service does not
    prevent the command from identifying the current Tor exit address.
    """
    errors: List[str] = []

    for host, path, parser_name in IP_ENDPOINTS:
        try:
            body = _https_get_through_tor(
                host,
                path,
            )

            parser = PARSERS[parser_name]
            ip_text = parser(body)

            # Validate both IPv4 and IPv6 responses.
            ipaddress.ip_address(ip_text)

            return ip_text

        except (
            OSError,
            ssl.SSLError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            errors.append(
                "{}: {}".format(host, exc)
            )

    raise OSError(
        "all IP services failed; {}".format(
            "; ".join(errors)
        )
    )


def show_current_ip() -> int:
    """
    Print the current Tor exit IP without requesting a new circuit.
    """
    try:
        exit_ip = get_tor_exit_ip()
        print(
            "Current Tor Exit IP: {}".format(exit_ip)
        )
        return 0

    except (
        OSError,
        ssl.SSLError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        print(
            "tor-newip: unable to determine Tor exit IP: {}".format(
                exc
            ),
            file=sys.stderr,
        )
        return 6


def rotate_and_show(wait_seconds: float) -> int:
    """
    Display the current exit IP, request a new circuit, and display the
    resulting exit IP.
    """
    try:
        old_ip = get_tor_exit_ip()
        print(
            "Old IP: {}".format(old_ip)
        )

    except (
        OSError,
        ssl.SSLError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        print(
            "tor-newip: unable to determine current Tor exit IP: {}".format(
                exc
            ),
            file=sys.stderr,
        )
        return 6

    result = request_new_circuit()

    if result != 0:
        return result

    print(
        "Waiting {:g} seconds for a new circuit...".format(
            wait_seconds
        )
    )

    time.sleep(wait_seconds)

    try:
        new_ip = get_tor_exit_ip()

    except (
        OSError,
        ssl.SSLError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        print(
            "tor-newip: unable to determine new Tor exit IP: {}".format(
                exc
            ),
            file=sys.stderr,
        )
        return 6

    print(
        "New IP: {}".format(new_ip)
    )

    if new_ip == old_ip:
        print(
            "Warning: Tor returned the same exit IP.",
            file=sys.stderr,
        )
        return 7

    print(
        "Circuit changed successfully."
    )

    return 0


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Rotate the local Tor circuit or display its current exit IP."
        )
    )

    mode = parser.add_mutually_exclusive_group()

    mode.add_argument(
        "-i",
        "--ip",
        action="store_true",
        help=(
            "display the current Tor exit IP without rotating"
        ),
    )

    mode.add_argument(
        "-r",
        "--rotate-and-show",
        action="store_true",
        help=(
            "rotate the circuit and display the old and new exit IPs"
        ),
    )

    parser.add_argument(
        "--wait",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help=(
            "seconds to wait before checking the new IP, default: 5"
        ),
    )

    args = parser.parse_args()

    if args.wait < 0:
        parser.error(
            "--wait must be zero or greater"
        )

    return args


def main() -> int:
    """
    Run the requested command.
    """
    args = parse_args()

    if args.ip:
        return show_current_ip()

    if args.rotate_and_show:
        return rotate_and_show(args.wait)

    # Preserve the original no-argument behavior for the systemd timer.
    return request_new_circuit()


if __name__ == "__main__":
    sys.exit(main())
