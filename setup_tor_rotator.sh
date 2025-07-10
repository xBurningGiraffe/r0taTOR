#!/usr/bin/env bash
# setup-tor-rotator.sh – install Tor + proxychains + tor-newip timer
# Usage: sudo bash setup-tor-rotator.sh

set -euo pipefail

USER_NAME="${SUDO_USER:-$(whoami)}"
USER_HOME=$(eval echo "~$USER_NAME")
TOR_BIN=/usr/bin/tor-newip
PY_SCRIPT=/tmp/tor-newip.py

need_pkgs=(
  tor
  proxychains4
  python3
  python3-pip
  build-essential
  libffi-dev
  libssl-dev
)

echo "[+] Checking packages …"
missing_pkgs=()
for p in "${need_pkgs[@]}"; do
    dpkg -s "$p" &>/dev/null || missing_pkgs+=("$p")
done

if ((${#missing_pkgs[@]})); then
    echo "[+] Installing: ${missing_pkgs[*]}"
    apt-get update -qq
    apt-get install -y "${missing_pkgs[@]}"
else
    echo "[+] All required packages already installed."
fi

if ! command -v pyinstaller &>/dev/null; then
    echo "[+] Installing pyinstaller …"
    pip3 install --quiet pyinstaller
else
    echo "[+] pyinstaller already present."
fi

if [[ ! -x $TOR_BIN ]]; then
    echo "[+] Building tor-newip …"
    cat > "$PY_SCRIPT" <<'PY'
#!/usr/bin/env python3
import pathlib, socket, sys, time
COOKIE = pathlib.Path("/run/tor/control.authcookie")
def send(s, line): s.sendall(line.encode()+b"\r\n"); return s.recv(1024)
def main():
    if COOKIE.stat().st_size!=32: sys.exit("cookie wrong size")
    hex_ck = COOKIE.read_bytes().hex()
    with socket.create_connection(("127.0.0.1",9051),timeout=4) as s:
        if not send(s,f"AUTHENTICATE {hex_ck}").startswith(b"250"): sys.exit("auth")
        if not send(s,"SIGNAL NEWNYM").startswith(b"250"): sys.exit("newnym")
        send(s,"QUIT")
    print(time.strftime("[%F %T]"),"new circuit")
if __name__=="__main__": main()
PY
    chmod +x "$PY_SCRIPT"
    pyinstaller --onefile --clean -q "$PY_SCRIPT"
    install -m0755 dist/tor-newip "$TOR_BIN"
    rm -rf build dist "$PY_SCRIPT" tor-newip.spec
else
    echo "[+] /usr/bin/tor-newip already exists – skipping build."
fi

TORRC=/etc/tor/torrc
block='##### tor-rotator #####'
if ! grep -q "$block" "$TORRC"; then
    echo "[+] Patching torrc …"
    cat >> "$TORRC" <<EOF
$block
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
MaxCircuitDirtiness 600
$block
EOF
    systemctl restart tor
else
    echo "[+] torrc already contains our settings."
fi

usermod -aG debian-tor "$USER_NAME"
echo "[+] User $USER_NAME ensured in debian-tor group."

unit_changed=0
write_unit() {
    local path="$1" content="$2"
    if [[ ! -f $path ]] || ! cmp -s <(echo "$content") "$path"; then
        echo "$content" > "$path"
        unit_changed=1
    fi
}

write_unit /etc/systemd/system/tor-newip.service \
"[Unit]
Description=Tor NEWNYM oneshot
Requires=tor.service
After=tor.service
[Service]
Type=oneshot
ExecStart=$TOR_BIN
User=debian-tor
Group=debian-tor"

write_unit /etc/systemd/system/tor-newip.timer \
"[Unit]
Description=Run tor-newip every minute
[Timer]
OnBootSec=1min
OnUnitActiveSec=60sec
Unit=tor-newip.service
Persistent=true
[Install]
WantedBy=timers.target"

if ((unit_changed)); then
    echo "[+] Enabling & starting systemd timer …"
    systemctl daemon-reload
    systemctl enable --now tor-newip.timer
else
    echo "[+] systemd units already up-to-date."
fi

PCONF="$USER_HOME/.proxychains/proxychains.conf"
if [[ ! -f $PCONF ]]; then
    echo "[+] Initialising user proxychains.conf"
    mkdir -p "$USER_HOME/.proxychains"
    cp /etc/proxychains.conf "$PCONF"
    sed -i '/^\[ProxyList\]/,/^\s*$/c\[ProxyList]\nsocks5 127.0.0.1 9050' "$PCONF"
    sed -i '/^dynamic_chain/s/^#*//;/^quiet_mode/s/^#*//;/^proxy_dns/s/^#*//' "$PCONF"
    chown -R "$USER_NAME":"$USER_NAME" "$USER_HOME/.proxychains"
else
    echo "[+] proxychains.conf already present – leaving untouched."
fi

echo
echo "====== DONE ======"
echo "Log out/in to refresh group membership."
echo "Test rotation: proxychains4 -q curl https://check.torproject.org/api/ip"
