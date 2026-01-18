import customtkinter as ctk
import pyperclip, os, hashlib, config, cv2, aes, io
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
import numpy as np
from PIL import Image, ImageFilter

def read_qr_from_bytes(image_bytes):
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return None
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img)
        return data
    except Exception as e:
        return None

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
    config.toast_label = ctk.CTkLabel(root, text="✅ Copied to clipboard", fg_color="#22cc22", text_color="white",
                           font=("Segoe UI", 12), corner_radius=8, padx=12, pady=6)
    config.toast_label.place(relx=0.5, rely=0.9, anchor='s')
    root.after(1500, config.toast_label.destroy)

def save_password(password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    pw_path = os.path.join(config.APP_FOLDER, "password.hash")
    try:
        with open(pw_path, "w") as f:
            f.write(hashed)
        try:
            os.chmod(pw_path, 0o600)
        except Exception:
            pass
        return True
    except Exception:
        return False

def get_stored_password():
    pw_path = os.path.join(config.APP_FOLDER, "password.hash")
    try:
        with open(pw_path, "r") as f:
            return f.read().strip()
    except Exception:
        return None

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
                except Exception as e:
                    continue
    except FileNotFoundError: pass
    return decrypted_otps

def get_qr_image(enc_img_path, key, blur=True):
    if not os.path.exists(enc_img_path):
        return None
    crypto = aes.Crypto(key)
    try:
        with open(enc_img_path, 'rb') as f:
            enc_data = f.read()
        img_bytes = crypto.decrypt_bytes(enc_data)
        img = Image.open(io.BytesIO(img_bytes))
        if img.mode != "RGBA":
            img = img.convert("RGBA")
        img = img.resize((200, 200), Image.Resampling.LANCZOS)
        if blur:
            img = img.filter(ImageFilter.GaussianBlur(radius=15))
        return img
    except Exception:
        return None

def delete_credential(platform_to_delete, uri_to_delete, key, path_to_delete=None):
    if not os.path.exists(config.ENCODED_FILE):
        return False
    
    crypto = aes.Crypto(key)
    new_lines = []
    deleted = False
    
    platform_to_delete = platform_to_delete.strip()
    uri_to_delete = uri_to_delete.strip()
    if path_to_delete:
        path_to_delete = path_to_delete.strip()

    try:
        with open(config.ENCODED_FILE, 'r') as f:
            lines = f.readlines()
            
        for line in lines:
            line = line.strip()
            if not line: continue
            
            try:
                decrypted_line = crypto.decrypt_aes(line)
            except Exception:
                new_lines.append(line)
                continue

            platform, uri, enc_img_path = None, None, None
            if '|' in decrypted_line:
                parts = decrypted_line.split('|')
                if len(parts) == 3:
                    platform, uri, enc_img_path = [p.strip() for p in parts]
            elif ': ' in decrypted_line:
                parts = decrypted_line.split(': ', 1)
                platform = parts[0].strip()
                enc_img_path = parts[1].strip()

            is_match = False
            if platform == platform_to_delete:
                if uri and uri == uri_to_delete:
                    is_match = True
                elif enc_img_path and (enc_img_path == uri_to_delete or (path_to_delete and enc_img_path == path_to_delete)):
                    is_match = True

            if is_match:
                if enc_img_path and enc_img_path != "NONE" and os.path.exists(enc_img_path):
                    try:
                        os.remove(enc_img_path)
                    except Exception:
                        pass
                deleted = True
                continue
            
            new_lines.append(line)
            
        if deleted:
            with open(config.ENCODED_FILE, 'w') as f:
                for nl in new_lines:
                    f.write(nl + "\n")
            return True
    except Exception:
        pass
        
    return False

def bind_enter(root, button):
    root.unbind_all("<Return>")
    root.bind_all("<Return>", lambda event: button.invoke())
