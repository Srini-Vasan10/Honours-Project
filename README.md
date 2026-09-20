# Cryptographic Security Gateway for Secure Optical QR Communication

A working prototype: a laptop (sender) encrypts a file, splits it into QR
frames, and displays them on screen. A phone (receiver, just a webpage —
no app install) scans the frames with its camera, verifies each one
cryptographically, reassembles the file, decrypts it, and lets you
download it — all without any network connection between the two devices.

## Files

- `crypto_utils.py` — core crypto/framing logic (AES-256-GCM, SHA-256,
  frame format, per-frame authentication). Used by the sender.
- `sender.py` — desktop GUI (Tkinter). Pick a file, get a receiving code,
  and display the QR frame sequence.
- `receiver.html` — single self-contained webpage for the phone. Open it
  in any mobile browser, enter the receiving code, point the camera at
  the laptop screen.
- `requirements.txt` — Python dependencies for the sender.

## Setup

### 1. Sender (laptop)

```bash
pip install -r requirements.txt
python3 sender.py
```

A window opens. Click **Select File** (keep it under ~50 KB for a smooth
demo — see "File size limits" below), then note the **receiving code**
shown on screen.

### 2. Receiver (phone)

You need `receiver.html` on your phone and open it in a mobile browser
(Chrome/Safari). Two easy ways to get it onto the phone:

**Option A — same WiFi network (simplest):**
On the laptop, in the project folder, run:
```bash
python3 -m http.server 8000
```
Find your laptop's local IP (e.g. `192.168.1.5`) and on the phone browser
go to `http://192.168.1.5:8000/receiver.html`.

> Note: this only serves the *webpage* over WiFi for convenience — the
> actual file transfer still happens purely optically (screen → camera).
> If you want a true zero-network demo, use Option B instead.

**Option B — fully offline:**
Airdrop / USB-transfer `receiver.html` directly onto the phone once
beforehand, and open it from local storage / a file browser with "Open
in browser". After that, no network is needed for any transfer — this
is the setup to use for your actual air-gapped demo.

### 3. Run the transfer

1. On the phone page, enter the receiving code exactly as shown on the
   laptop, tap **Start Scanning**, and allow camera access.
2. On the laptop, click **Start Sending**. The QR frames cycle automatically.
3. Point the phone camera at the laptop screen. Watch the frame meter
   fill in on the phone as frames are verified and stored.
4. Once all frames arrive, the phone automatically decrypts and shows a
   **Download File** button, with a pass/fail SHA-256 integrity result.

## IMPORTANT: shared key

Both `sender.py` and `receiver.html` have a hardcoded `SHARED_KEY_HEX`
constant — they **must match exactly** (this is your pre-shared AES-256
key for the prototype). They already match as shipped. If you regenerate
one, copy the same hex string into the other file.

This is a deliberate MVP simplification — see "Future work" below.

## File size limits

QR codes cap out around ~2-3 KB of data each. This project uses ~1.45 KB
ciphertext chunks per frame (after header + base64 overhead, each QR
holds ~2 KB of text). Practical guidance:

| File size | Approx. QR frames | Demo feel |
|---|---|---|
| ≤ 20 KB | ≤ 15 frames | Fast, smooth |
| 50 KB | ~35 frames | Good demo size |
| 200 KB+ | 140+ frames | Slow, not recommended for live demo |

Don't try to demo multi-MB files live — that's a fundamental optical
bandwidth limit, not a bug. Use a small text file, a certificate, or a
compressed image for your demo.

## What's actually being verified (for your viva/report)

Each QR frame carries, on top of its encrypted chunk:
- **Receiving code (session ID)** — rejects frames from any other session
- **Frame number + total frames** — enables sequencing and missing-frame detection
- **Truncated SHA-256 chunk hash** — catches corruption/modification of that chunk
- **AES-GCM authentication tag** — cryptographically proves the frame wasn't tampered with
- A **replay cache** on the receiver rejects any frame number seen twice

The whole file is *also* separately encrypted end-to-end with AES-256-GCM
before chunking, and its SHA-256 hash is checked again after full
reassembly and decryption — so integrity is checked both per-frame and
for the whole file.

## Demonstrating attacks (for your viva)

- **Tamper**: modify a QR image's content before scanning → integrity/auth failure
- **Replay**: let the phone scan the same frame twice → "REPLAY DETECTED" in the log
- **Wrong session**: start the receiver with a different receiving code → all frames rejected as "INVALID SESSION"
- **Missing frame**: cover the screen mid-sequence, skipping a frame → frame meter shows the gap, transfer waits/fails until it's rescanned

## Future work (mentioned, not built, in this MVP)

- **Key exchange**: replace the hardcoded pre-shared key with an X25519
  handshake (e.g., as an extra QR exchange step before the transfer).
- **Blockchain proof**: log `{session_id, file_hash, timestamp}` to a
  simple local hash-chained ledger for tamper-evident proof of transfer.
- **Forward error correction**: add Reed-Solomon/fountain coding so a few
  dropped frames don't require a manual rescan.
