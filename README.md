r0taTOR

A lightweight workflow for Linux that forces a **fresh Tor exit IP
every minute**, intended for red-teamers and privacy-minded testers who
run command-line tools through `proxychains`.

Contents
--------
1. tor-newip.py        – Python 3 helper for rotating and inspecting Tor exit IPs
2. tor-newip.service   – oneshot systemd unit that runs the helper
3. tor-newip.timer     – systemd timer that fires the service every 60 s
4. README.md           – this file

How it works
------------
* All CLI traffic is sent to `127.0.0.1:9050` through **proxychains-ng**.
* Every minute `tor-newip.timer` triggers `tor-newip.service`.
* The service runs `tor-newip` **as the debian-tor user**, which:
  1. Authenticates with Tor’s control port via the 32-byte cookie.
  2. Sends `SIGNAL NEWNYM`, forcing Tor to build new circuits.
* New TCP sockets opened after that rotate out on a brand-new exit IP.
* IP inspection requests are sent directly through Tor's local SOCKS5 proxy
  and verified using the Tor Project IP-check API.

Prerequisites
-------------
* Debian/Ubuntu (should also work on any systemd-based distro)
* Packages: `tor`, `proxychains4`, `python3`, `python3-pip`
* Your user added to the **debian-tor** group:

      sudo usermod -aG debian-tor $USER && newgrp debian-tor

Quick install
-------------
```bash
# 1. copy tor-newip.py, service & timer to this server
sudo install -m0755 tor-newip.py /usr/bin/tor-newip

# 2. torrc tweaks
sudo tee -a /etc/tor/torrc >/dev/null <<'EOF'
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
MaxCircuitDirtiness 600
EOF
sudo systemctl restart tor

# 3. systemd
sudo cp tor-newip.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tor-newip.timer
```

Usage
-----
Rotate the Tor circuit. This remains the default behavior used by the systemd
service and timer:

```bash
tor-newip
```

Display the current Tor exit IP without rotating the circuit:

```bash
tor-newip --ip
# Short form
tor-newip -i
```

Rotate the circuit, then display the old and new exit IPs:

```bash
tor-newip --rotate-and-show
# Short form
tor-newip -r
```

Change the delay before checking the new IP:

```bash
tor-newip --rotate-and-show --wait 8
```

The IP-check modes fail rather than reporting an address when the Tor Project
API does not confirm that the request originated from the Tor network.
