# Open issue — the WARP tunnel connects, then disappears

Recorded 2026-09-17 so the diagnosis is not lost. **Not fixed.**

## Symptom

The app reports `Connected! Cloudflare WARP tunnel active.` and the tunnel
service briefly shows `STATE : 4 RUNNING`. Minutes later:

- the `WireGuardTunnel$wgcf-profile` service no longer exists
- no Wintun network adapter is present
- the only default route is `0.0.0.0/0 → Wi-Fi` (no `0.0.0.0/1` +
  `128.0.0.0/1` split-default pair, so nothing is being tunnelled)
- public IP is the ISP's, not Cloudflare's

So the UI claims success while no traffic goes through the tunnel.

## Evidence gathered

```
sc query WireGuardTunnel$wgcf-profile     RUNNING, then "does not exist" 4 min later
Get-NetAdapter                            Wi-Fi, Bluetooth, Sophos TAP, PANGP — no wgcf-profile
Get-NetRoute 0.0.0.0/0                    NextHop 192.170.0.1, InterfaceAlias Wi-Fi
curl api.ipify.org                        139.5.9.101  (ISP, not Cloudflare)
```

The generated config at `C:\OnamVPN\wgcf-profile.conf` is well-formed:
correct `AllowedIPs = 0.0.0.0/0, ::/0`, endpoint `162.159.193.1:2408`,
`MTU = 1280`.

## Leading hypothesis — unconfirmed

`WARP_PRIVATE_KEY` is hardcoded at `vpn_core/real_windows_wireguard.py:27` and
committed to the repository.

Cloudflare WARP requires a key **registered to an account** via their
device-registration API. A key that was registered once and then shared by
every copy of this project is likely deregistered, rate-limited, or simply
expired. A WireGuard peer whose key the server does not recognise gets no
handshake response — the interface comes up, never completes a handshake, and
the tunnel is torn down.

That matches the observed sequence exactly. It is still a hypothesis.

## What to check first, next session

1. Launch the app and let it auto-connect. File logging now works (see
   below), so `%APPDATA%\OnamVPN\logs\onamvpn_<date>.log` will have the full
   sequence.
2. While the tunnel is briefly up, check for a handshake:
   ```
   "C:\Program Files\WireGuard\wg.exe" show
   ```
   `latest handshake` never being set confirms the key hypothesis.
3. WireGuard's own log is more detailed than ours:
   ```
   "C:\Program Files\WireGuard\wireguard.exe" /dumplog
   ```
   Needs elevation. This will say why the tunnel stopped.

## If the key is the problem

Registering a fresh WARP key needs Cloudflare's device API — `wgcf` is the
usual tool for this. That produces a key registered to a new device, which
this project would then need to store per-installation rather than hardcode.

Note the key currently in the source is a real private key in a public
repository. Whatever replaces it should not be committed.

## Fixed along the way (these are done)

- **File logging never worked.** `setup_logger()` attached its handler to a
  logger named `"OnamVPN"`, but modules use `get_logger(__name__)` —
  `vpn_core.*`, `gui.*` — which are not its children, so records propagated to
  the root logger and never reached the file. Every log in
  `%APPDATA%\OnamVPN\logs` was 0 bytes going back to October 2025. Handlers
  now attach to the root logger.
- DNS-leak rules blocked *all* DNS (Windows Firewall evaluates Block before
  Allow) — still unverified in practice, because testing it cuts network
  access.
- Connect/disconnect blocked the GUI thread for 4-10 s.
- A disconnect clicked during a connect was silently discarded.
- Startup ping scan was serial: 6.2 s → 1.1 s.
- `WinError 32` on every connect from staging a config onto itself.
- Three ERROR lines at every startup from removing tunnels that never existed.

## Machine state as of writing

Clean. No OnamVPN firewall rules, no tunnel services, DNS resolving, internet
reachable. Nothing needs undoing before picking this up again.

## Scope note

This affects the VPN client only. All eight CN + OS lab modules are
independent of it and fully working — `python main.py --labs`, 457 tests
passing. The native tunnel in `netlab/native/` is our own implementation and
does not use Cloudflare at all.
