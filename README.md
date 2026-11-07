# thorctl

Linux configuration tool for the Fantech Thor II X16 V2 gaming mouse (PixArt `093a:2533`).
The vendor software is Windows-only. This tool speaks the mouse's protocol directly over usbfs,
using only the Python standard library.

> **Status:** protocol decoded from Windows USB captures. Not yet tested on real hardware.

## What the mouse stores

| Setting | Supported |
|---|---|
| 4 DPI stages (200–4200 DPI, steps of 200) | stage 1: full range; stages 2–4: up to 3200 for now |
| Report rate 125 / 250 / 500 / 1000 Hz | yes |
| Profiles | kept by the Windows app, not the mouse (it re-writes the DPI stages on switch) |
| Button remap, macros | done host-side by the Windows driver; on Linux use evdev remapping (e.g. input-remapper) |
| Pointer / wheel / double-click speed | Windows settings, not the mouse; use your desktop's mouse settings |

## Protocol

USB vendor control requests to the device (not HID reports):

| Op | bmRequestType | bRequest | wValue | wIndex | wLength |
|---|---|---|---|---|---|
| write register | `0x40` | `0x01` | `0x0100` | `value << 8 \| reg` | 0 |
| read register  | `0xC0` | `0x01` | `0x0100` | `reg` | 1 |

Before accessing settings, the driver sends `7f←00, 09←00, 00←00 (wValue 0), 09←5a, 7f←01`
(unlock, then register bank 1), with about 110 ms between requests.

| Register | Meaning |
|---|---|
| `02`–`05` | DPI stages 1–4: low nibble = bits 0–3 of `DPI/200 - 1` |
| `08` bit 5 | bit 4 of stage 1's DPI index |
| `0e` bits 7:6 | report rate: 0 = 1000, 1 = 500, 2 = 250, 3 = 125 Hz (the mouse re-enumerates) |

## Usage

Needs write access to `/dev/bus/usb/BBB/DDD` (root, for now).

```bash
sudo python3 -I thorctl.py status              # decode current settings
sudo python3 -I thorctl.py dpi 1 1600          # dry run: prints the writes it would send
sudo python3 -I thorctl.py --apply dpi 1 1600  # send them (saves a backup first)
sudo python3 -I thorctl.py --apply rate 1000
sudo python3 -I thorctl.py --apply restore ~/.local/state/thorctl/backup-*.json
```

Every command sends the same unlock and bank-select sequence the Windows driver sends on each
connect, then only reads. Setting changes go out only with `--apply`.
Backups go to `~/.local/state/thorctl/` (under `sudo`, that's root's home directory).

## Development

```bash
python3 -I -m unittest discover -s tests       # offline, no mouse needed
python3 -I tools/usbpcap.py capture.pcapng --regs   # decode a Windows USBPcap capture
```

| Path | What |
|---|---|
| `thorctl.py` | The tool |
| `tests/` | Offline encoder tests built from captured traffic |
| `tools/usbpcap.py` | Decode HID and vendor control transfers from a USBPcap `.pcapng` |
| `tools/probe.py` | HID feature-report probe (this mouse stalls them; kept for reference) |
| `tools/unpack/` | Stdlib-only installer unpackers: InstallShield overlay → MSI cab → files |
| `captures/` | USB captures (pcaps git-ignored) |
