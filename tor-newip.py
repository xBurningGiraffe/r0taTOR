#!/usr/bin/env python3
"""
tor-newip.py
Ask the local Tor control port (127.0.0.1:9051) to build a new circuit,
or display the current Tor exit IP.

• Uses cookie authentication, so no password is required.
• Exits 0 on success; non-zero on failure (handy for systemd).
"""

import argparse
import ipaddress
import pathlib
import socket
import ssl
import sys
