import tkinter as tk
import pyperclip
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
import os
import hashlib
import keyring
import config
import cv2
import numpy as np
import aes
from PIL import Image, ImageTk, ImageFilter
import io

def read_qr_from_bytes(image_bytes):
    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None: return None
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(img)
    return data

def load_otps_from_decrypted(decrypted_otps):
    entries = [(name.strip(), uri.strip(), img_path) for name, uri, img_path in decrypted_otps if "otpauth://" in uri]
    return sorted(entries, key=lambda x: x[0].lower())

def clean_uri(uri):
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)
    label = unquote(parsed.path.split('/')[-1])
    if ':' in label:
        label_issuer, username = label.split(':', 1)
    else:
        label_issuer = username = label
    query_issuer = query.get("issuer", [label_issuer])[0]
    if label_issuer != query_issuer:
        query['issuer'] = [label_issuer]
    parsed = parsed._replace(query=urlencode(query, doseq=True))
    return urlunparse(parsed), label_issuer, username

def copy_and_toast(var, root):
    pyperclip.copy(var.get())
    if config.toast_label: config.toast_label.destroy()
    config.toast_label = tk.Label(root, text="✅ Copied to clipboard", bg="#444", fg="white",
                           font=("Segoe UI", 10), padx=12, pady=6)
    config.toast_label.place(relx=0.5, rely=1.0, anchor='s')
    root.after(1500, config.toast_label.destroy)

def on_mousewheel(event):
    if config.canvas:
        # Get current scroll position
        top, bottom = config.canvas.yview()
        # Prevent scrolling past boundaries
        if event.delta > 0 and top <= 0:
            return  # Already at top, don't scroll up
        if event.delta < 0 and bottom >= 1:
            return  # Already at bottom, don't scroll down
        config.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

def save_password(password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    keyring.set_password(config.SERVICE_NAME, config.USERNAME, hashed)

def get_stored_password():
    return keyring.get_password(config.SERVICE_NAME, config.USERNAME)

def decode_encrypted_file():
    if not config.decrypt_key: return []
    decrypted_otps = []
    crypto = aes.Crypto(config.decrypt_key)
    try:
        with open(config.ENCODED_FILE, 'r') as infile:
            for line in infile:
                line = line.strip()
                if not line: continue
                try:
                    decrypted_line = crypto.decrypt_aes(line)
                    if '|' in decrypted_line:
                        parts = decrypted_line.split('|')
                        if len(parts) == 3:
                            platform, uri, enc_img_path = parts
                            decrypted_otps.append((platform, uri, enc_img_path))
                    elif ': ' in decrypted_line:
                        platform, enc_img_path = decrypted_line.split(': ', 1)
                        
                        if os.path.exists(enc_img_path):
                            with open(enc_img_path, 'rb') as f:
                                enc_data = f.read()
                            img_bytes = crypto.decrypt_bytes(enc_data)
                            uri = read_qr_from_bytes(img_bytes)
                            if uri:
                                decrypted_otps.append((platform, uri, enc_img_path))
                except Exception:
                    continue
    except FileNotFoundError: pass
    return decrypted_otps

def get_qr_image(enc_img_path, key, blur=True):
    if not os.path.exists(enc_img_path): return None
    crypto = aes.Crypto(key)
    try:
        with open(enc_img_path, 'rb') as f:
            enc_data = f.read()
        img_bytes = crypto.decrypt_bytes(enc_data)
        img = Image.open(io.BytesIO(img_bytes))
        img = img.resize((200, 200), Image.Resampling.LANCZOS)
        if blur:
            img = img.filter(ImageFilter.GaussianBlur(radius=15))
        return ImageTk.PhotoImage(img)
    except Exception:
        return None

def delete_credential(platform_to_delete, uri_to_delete, key):
    if not os.path.exists(config.ENCODED_FILE):
        return False
    
    crypto = aes.Crypto(key)
    new_lines = []
    deleted = False
    
    try:
        with open(config.ENCODED_FILE, 'r') as f:
            lines = f.readlines()
            
        for line in lines:
            line = line.strip()
            if not line: continue
            
            decrypted_line = crypto.decrypt_aes(line)
            platform, uri, enc_img_path = None, None, None

            if '|' in decrypted_line:
                parts = decrypted_line.split('|')
                if len(parts) == 3:
                    platform, uri, enc_img_path = parts
            elif ': ' in decrypted_line:
                platform, enc_img_path = decrypted_line.split(': ', 1)
                # For legacy, we might need to read the URI to match, 
                # but usually platform + path is enough.
                if enc_img_path == uri_to_delete: # In legacy, we passed path as 2nd arg
                     uri = uri_to_delete 

            # Match by platform and uri (or path for legacy)
            if platform == platform_to_delete and (uri == uri_to_delete or enc_img_path == uri_to_delete):
                if enc_img_path and enc_img_path != "NONE" and os.path.exists(enc_img_path):
                    os.remove(enc_img_path)
                deleted = True
                continue
            
            new_lines.append(line)
            
        if deleted:
            with open(config.ENCODED_FILE, 'w') as f:
                for nl in new_lines:
                    f.write(nl + "\n")
            return True
    except Exception as e:
        print(f"Deletion failed: {e}")
        
    return False

def bind_enter(root, button):
    root.unbind_all("<Return>")
    root.bind_all("<Return>", lambda event: button.invoke())
