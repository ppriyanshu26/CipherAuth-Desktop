import customtkinter as ctk
import os, hashlib, config, cv2, aes, io, json, time, sys, socket, threading, subprocess, pyotp, qrcode
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
import numpy as np
from PIL import Image, ImageFilter

def copy_to_clipboard(text):
    try:
        import pyperclip
        pyperclip.copy(text)
        return True
    except Exception:
        pass
    
    if sys.platform == "win32":
        try:
            process = subprocess.Popen(['clip'], stdin=subprocess.PIPE)
            process.communicate(text.encode('utf-8'))
            return True
        except Exception:
            pass
    elif sys.platform == "darwin":
        try:
            process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
            process.communicate(text.encode('utf-8'))
            return True
        except Exception:
            pass
    else:
        for cmd in ['xclip', 'xsel', 'wl-copy']:
            try:
                if cmd == 'wl-copy':
                    process = subprocess.Popen([cmd], stdin=subprocess.PIPE)
                else:
                    process = subprocess.Popen([cmd, '-selection', 'clipboard'], stdin=subprocess.PIPE)
                process.communicate(text.encode('utf-8'))
                return True
            except Exception:
                continue
    
    return False

def read_qr_from_bytes(image_bytes):
    try:
        img = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_COLOR)
        if img is None: return None
        data, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
        return data
    except: return None

def load_otps_from_decrypted(otps):
    return sorted(otps, key=lambda x: x.get('platform', '').lower())

def clean_uri(uri):
    if not uri or "otpauth://" not in uri: return "", "", ""
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)
    label_issuer, _, username = (lambda l: (l.split(':')[0], None, l.split(':')[1]) if ':' in l else (l, None, l))(unquote(parsed.path.split('/')[-1]))
    if label_issuer != (qi := query.get("issuer", [label_issuer])[0]):
        query['issuer'] = [label_issuer]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True))), label_issuer, username

def generate_id(platform, secret, salt=None):
    salt = salt or str(time.time())
    return hashlib.sha256(f"{platform}{secret}{salt}".encode()).hexdigest()

def save_otps_encrypted(otp_list, key):
    encrypted = aes.Crypto(key).encrypt_aes(json.dumps(otp_list))
    with open(config.ENCODED_FILE, 'w') as f:
        f.write(encrypted)

def decode_encrypted_file():
    if not config.decrypt_key or not os.path.exists(config.ENCODED_FILE): return []
    crypto = aes.Crypto(config.decrypt_key)
    try:
        with open(config.ENCODED_FILE, 'r') as f:
            if (content := f.read().strip()):
                data = json.loads(crypto.decrypt_aes(content))
                return data if isinstance(data, list) else []
    except: pass
    return []

def extract_secret_from_uri(uri):
    try:
        return parse_qs(urlparse(uri).query).get('secret', [None])[0]
    except: return None

def load_image_paths():
    if not os.path.exists(config.IMAGE_PATH_FILE): return {}
    try:
        with open(config.IMAGE_PATH_FILE, 'r') as f:
            return json.loads(content) if (content := f.read().strip()) else {}
    except: return {}

def save_image_path(cred_id, enc_img_path):
    try:
        paths = load_image_paths()
        paths[cred_id] = enc_img_path
        with open(config.IMAGE_PATH_FILE, 'w') as f:
            f.write(json.dumps(paths))
        return True
    except: return False

def get_image_path(cred_id):
    return load_image_paths().get(cred_id)

def delete_image_path(cred_id):
    try:
        paths = load_image_paths()
        if cred_id in paths:
            del paths[cred_id]
            with open(config.IMAGE_PATH_FILE, 'w') as f:
                f.write(json.dumps(paths))
    except: pass
    return True

def generate_qr_from_secret(platform, username, secret):
    try:
        import pyotp, qrcode
        secret = secret.replace(" ", "").upper()
        pyotp.TOTP(secret).now()
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=platform)
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        if img.mode != "RGBA": img = img.convert("RGBA")
        img = img.resize((200, 200), Image.Resampling.LANCZOS)
        return img
    except: return None

def get_qr_image(cred_id, key, blur=True, cred_data=None):
    enc_img_path = get_image_path(cred_id)
    if enc_img_path and os.path.exists(enc_img_path):
        try:
            img_bytes = aes.Crypto(key).decrypt_bytes(open(enc_img_path, 'rb').read())
            img = Image.open(io.BytesIO(img_bytes))
            if img.mode != "RGBA": img = img.convert("RGBA")
            img = img.resize((200, 200), Image.Resampling.LANCZOS)
            return img.filter(ImageFilter.GaussianBlur(radius=15)) if blur else img
        except: pass
    
    if cred_data and 'secretcode' in cred_data:
        img = generate_qr_from_secret(cred_data.get('platform', ''), cred_data.get('username', ''), cred_data.get('secretcode', ''))
        return img.filter(ImageFilter.GaussianBlur(radius=15)) if (blur and img) else img
    
    return None

def save_password(password):
    try:
        hashed = hashlib.sha256(password.encode()).hexdigest()
        pw_path = os.path.join(config.APP_FOLDER, "password.hash")
        with open(pw_path, "w") as f: f.write(hashed)
        try: os.chmod(pw_path, 0o600)
        except: pass
        return True
    except: return False

def save_device_name(name):
    try:
        with open(config.DEVICE_NAME_FILE, 'w') as f:
            f.write(name.strip())
        return True
    except: return False

def load_device_name():
    try:
        if os.path.exists(config.DEVICE_NAME_FILE):
            with open(config.DEVICE_NAME_FILE, 'r') as f:
                content = f.read().strip()
                return content if content else "Authenticator Desktop"
    except: pass
    return "Authenticator Desktop"

class SyncDeviceAdvertiser:
    BROADCAST_PORT = 34567
    SERVICE_TYPE = "CIPHERAUTH_SYNC"
    
    def __init__(self, device_name):
        self.device_name = device_name
        self.running = False
        self.thread = None
        self.sock = None
    
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self.broadcast_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
    
    def broadcast_loop(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            local_ip = self.get_local_ip()
            
            while self.running:
                try:
                    message = json.dumps({
                        "type": self.SERVICE_TYPE,
                        "device_name": self.device_name,
                        "ip": local_ip,
                        "timestamp": time.time()
                    }).encode('utf-8')
                    
                    self.sock.sendto(message, ('<broadcast>', self.BROADCAST_PORT))
                except Exception as e:
                    pass
                
                time.sleep(1)
        except Exception as e:
            pass
        finally:
            if self.sock:
                try:
                    self.sock.close()
                except:
                    pass

advertizer = None

def start_sync_broadcast(device_name):
    global advertizer
    if advertizer:
        advertizer.stop()
    advertizer = SyncDeviceAdvertiser(device_name)
    advertizer.start()

def stop_sync_broadcast():
    global advertizer
    if advertizer:
        advertizer.stop()
        advertizer = None

def discover_cipherauth_devices(exclude_device_name=None):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', SyncDeviceAdvertiser.BROADCAST_PORT))
        sock.settimeout(3)
        
        devices = {}
        start_time = time.time()
        
        while time.time() - start_time < 3:
            try:
                data, addr = sock.recvfrom(1024)
                message = json.loads(data.decode('utf-8'))
                
                if message.get('type') == SyncDeviceAdvertiser.SERVICE_TYPE:
                    device_name = message.get('device_name', 'Unknown')
                    
                    if exclude_device_name and device_name == exclude_device_name:
                        continue
                    
                    device_ip = message.get('ip', addr[0])
                    devices[device_name] = {
                        'name': device_name,
                        'ip': device_ip,
                        'timestamp': message.get('timestamp', 0)
                    }
            except socket.timeout:
                break
            except Exception as e:
                pass
        sock.close()
        return list(devices.values())
    except Exception as e:
        return []

def get_stored_password():
    try:
        return open(os.path.join(config.APP_FOLDER, "password.hash"), "r").read().strip()
    except: return None

def delete_credential(cred_id, key):
    otps = decode_encrypted_file()
    if not any(c['id'] == cred_id for c in otps): return False
    
    enc_img_path = get_image_path(cred_id)
    if enc_img_path and os.path.exists(enc_img_path):
        try: os.remove(enc_img_path)
        except: pass
    delete_image_path(cred_id)
    
    save_otps_encrypted([c for c in otps if c['id'] != cred_id], key)
    return True

def bind_enter(root, button):
    root.unbind_all("<Return>")
    root.bind_all("<Return>", lambda _: button.invoke())

def truncate(text, max_len, suffix="..."):
    return f"{text[:max_len]}{suffix}" if len(text) > max_len else text

def copy_and_toast(var, root):
    if copy_to_clipboard(var.get()):
        message = "✅ Copied to clipboard"
        color = "#22cc22"
    else:
        message = "⚠️ Copy failed"
        color = "#ff8866"
    
    if config.toast_label: config.toast_label.destroy()
    config.toast_label = ctk.CTkLabel(root, text=message, fg_color=color, text_color="white", font=("Segoe UI", 12), corner_radius=8, padx=12, pady=6)
    config.toast_label.place(relx=0.5, rely=0.9, anchor='s')
    root.after(1500, lambda: config.toast_label.destroy() if config.toast_label else None)

truncate_platform_name = lambda name: truncate(name, 50)
truncate_username = lambda username: truncate(username, 60)