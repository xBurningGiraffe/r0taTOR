r0taTOR

A lightweight workflow for Linux that forces a **fresh Tor exit IP
every minute**, intended for red-teamers and privacy-minded testers who
run command-line tools through `proxychains`.

Contents
--------
1. tor-newip.py        – Python 3 helper that issues SIGNAL NEWNYM
2. tor-newip.service   – oneshot systemd unit that runs the helper
3. tor-newip.timer     – systemd timer that fires the service every 60 s
4. README.txt          – this file

How it works
------------
* All CLI traffic is sent to `127.0.0.1:9050` through **proxychains-ng**.
* Every minute `tor-newip.timer` triggers `tor-newip.service`.
* The service runs `tor-newip` **as the debian-tor user**, which:
  1. Authenticates with Tor’s control port via the 32-byte cookie.
  2. Sends `SIGNAL NEWNYM`, forcing Tor to build new circuits.
* New TCP sockets opened after that rotate out on a brand-new exit IP.

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
