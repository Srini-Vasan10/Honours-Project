"""
sender.py — Cryptographic Security Gateway: Sender side

Run with:
    python3 sender.py

What it does:
1. Lets you pick a file (keep it small — under ~50 KB for a smooth demo).
2. Computes SHA-256 of the original file.
3. Encrypts the whole file with AES-256-GCM.
4. Splits the ciphertext into ~1.45 KB chunks.
5. Wraps each chunk into a signed/authenticated frame (see crypto_utils.py).
6. Generates a QR code image per frame.
7. Displays the receiving code (share this with the receiver) and cycles
   through the QR frames on screen for the phone to scan.

The AES key in this MVP is a hardcoded pre-shared key (see SHARED_KEY_HEX below).
Both sender.py and the receiver webpage must use the SAME key. This is intentional
for the prototype — proper key exchange (X25519) is future work.
"""

import os
import sys
import time
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import qrcode

import crypto_utils as cu

# --- Pre-shared key for the MVP (32 bytes = 64 hex chars = AES-256) ---
# IMPORTANT: this exact hex string must be pasted into the receiver webpage too.
SHARED_KEY_HEX = "3b1a9c4e7d2f8601b5a3c9d0e4f2178a6b3c5d7e9f0a1b2c3d4e5f60718293a4"
SHARED_KEY = bytes.fromhex(SHARED_KEY_HEX)

FRAME_DISPLAY_SECONDS = 1.2  # how long each QR is shown before moving to the next
MAX_FILE_SIZE = 50 * 1024  # 50 KB soft cap for a smooth demo


class SenderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptographic Security Gateway — Sender")
        self.root.configure(bg="#0D1117")
        self.root.geometry("520x680")

        self.frames_qr_images = []  # list of PIL ImageTk objects, in order
        self.current_index = 0
        self.playing = False
        self.receiving_code = None
        self.file_nonce = None

        self._build_ui()

    def _build_ui(self):
        FG = "#E6EDF3"
        DIM = "#8B949E"
        ACCENT = "#4ADE80"
        FONT = ("Courier New", 11)
        FONT_BOLD = ("Courier New", 13, "bold")

        title = tk.Label(self.root, text="SECURE OPTICAL QR TRANSFER — SENDER",
                          fg=ACCENT, bg="#0D1117", font=("Courier New", 14, "bold"))
        title.pack(pady=(16, 4))

        self.status_label = tk.Label(self.root, text="No file selected.",
                                      fg=DIM, bg="#0D1117", font=FONT, wraplength=480)
        self.status_label.pack(pady=(0, 10))

        pick_btn = tk.Button(self.root, text="Select File", command=self.select_file,
                              bg="#1F2933", fg=FG, font=FONT, relief="flat",
                              activebackground="#2D3A45", activeforeground=FG, padx=10, pady=6)
        pick_btn.pack(pady=4)

        self.code_label = tk.Label(self.root, text="Receiving code: ----",
                                    fg=FG, bg="#0D1117", font=FONT_BOLD)
        self.code_label.pack(pady=(10, 4))

        self.qr_canvas = tk.Label(self.root, bg="#0D1117")
        self.qr_canvas.pack(pady=10)

        self.frame_counter_label = tk.Label(self.root, text="", fg=DIM, bg="#0D1117", font=FONT)
        self.frame_counter_label.pack()

        btn_frame = tk.Frame(self.root, bg="#0D1117")
        btn_frame.pack(pady=14)

        self.play_btn = tk.Button(btn_frame, text="Start Sending", command=self.toggle_play,
                                   bg="#1F2933", fg=ACCENT, font=FONT, relief="flat",
                                   activebackground="#2D3A45", padx=10, pady=6, state="disabled")
        self.play_btn.grid(row=0, column=0, padx=6)

        self.speed_label = tk.Label(self.root, text=f"Frame interval: {FRAME_DISPLAY_SECONDS}s",
                                     fg=DIM, bg="#0D1117", font=FONT)
        self.speed_label.pack()

        self.log_text = tk.Text(self.root, height=8, bg="#161B22", fg=DIM, font=("Courier New", 9),
                                 relief="flat", wrap="word")
        self.log_text.pack(fill="x", padx=16, pady=(14, 10))
        self.log_text.config(state="disabled")

    def log(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"{message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def select_file(self):
        path = filedialog.askopenfilename(title="Select a file (keep it small, <50KB ideal)")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                file_data = f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Could not read file: {e}")
            return

        if len(file_data) > MAX_FILE_SIZE:
            proceed = messagebox.askyesno(
                "Large file warning",
                f"This file is {len(file_data)/1024:.1f} KB. Files over "
                f"{MAX_FILE_SIZE/1024:.0f} KB will need many QR frames and may be "
                f"slow/unreliable to scan. Continue anyway?"
            )
            if not proceed:
                return

        self.prepare_transfer(file_data, os.path.basename(path))

    def prepare_transfer(self, file_data: bytes, filename: str):
        self.log(f"File loaded: {filename} ({len(file_data)} bytes)")

        original_hash = cu.sha256_full(file_data)
        self.log(f"SHA-256: {original_hash.hex()[:16]}...")

        ciphertext, file_nonce = cu.encrypt_file(file_data, SHARED_KEY)
        self.file_nonce = file_nonce
        self.log(f"Encrypted with AES-256-GCM. Ciphertext size: {len(ciphertext)} bytes")

        chunks = cu.chunk_bytes(ciphertext)
        self.receiving_code = cu.generate_receiving_code()
        self.log(f"Split into {len(chunks)} chunk(s)")

        frames = [cu.build_frame(self.receiving_code, i, len(chunks), c)
                  for i, c in enumerate(chunks)]

        # Filename + file_nonce + original_hash need to reach the receiver too.
        # We send them as "frame 0" metadata by prepending a metadata frame.
        meta_payload = self._build_metadata_payload(filename, file_nonce, original_hash, len(chunks))
        meta_frame = cu.build_frame(self.receiving_code, 0xFFFF, len(chunks), meta_payload)
        # 0xFFFF frame_number marks this as the metadata frame (never a real chunk index).

        all_qr_texts = [cu.frame_to_qr_text(meta_frame)] + \
                        [cu.frame_to_qr_text(f) for f in frames]

        self.frames_qr_images = [self._make_qr_image(t) for t in all_qr_texts]
        self.current_index = 0

        code_str = cu.receiving_code_to_str(self.receiving_code)
        self.code_label.config(text=f"Receiving code: {code_str}")
        self.status_label.config(
            text=f"Ready — {len(chunks)} data frame(s) + 1 metadata frame. "
                 f"Share the receiving code with the receiver, then press Start."
        )
        self.play_btn.config(state="normal")
        self._show_frame(0)

    @staticmethod
    def _build_metadata_payload(filename: str, file_nonce: bytes, original_hash: bytes,
                                 total_chunks: int) -> bytes:
        name_bytes = filename.encode("utf-8")[:64]
        return (
            len(name_bytes).to_bytes(1, "big") + name_bytes
            + file_nonce
            + original_hash
            + total_chunks.to_bytes(2, "big")
        )

    def _make_qr_image(self, text: str):
        qr = qrcode.QRCode(
            version=None,  # auto-size to fit data
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=6,
            border=3,
        )
        qr.add_data(text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
        img = img.resize((360, 360), Image.NEAREST)
        return ImageTk.PhotoImage(img)

    def _show_frame(self, index):
        self.qr_canvas.config(image=self.frames_qr_images[index])
        total = len(self.frames_qr_images)
        label = "METADATA" if index == 0 else f"DATA FRAME {index}/{total - 1}"
        self.frame_counter_label.config(text=f"Showing: {label}  (frame {index + 1} of {total})")

    def toggle_play(self):
        self.playing = not self.playing
        self.play_btn.config(text="Pause" if self.playing else "Start Sending")
        if self.playing:
            self._play_loop()

    def _play_loop(self):
        if not self.playing:
            return
        self._show_frame(self.current_index)
        self.current_index = (self.current_index + 1) % len(self.frames_qr_images)
        self.root.after(int(FRAME_DISPLAY_SECONDS * 1000), self._play_loop)


if __name__ == "__main__":
    root = tk.Tk()
    app = SenderApp(root)
    root.mainloop()
