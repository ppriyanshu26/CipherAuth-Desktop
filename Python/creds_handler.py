import tkinter as tk
from tkinter import filedialog
import customtkinter as ctk
import os, time, hashlib, config, utils, aes, qrcode, io, pyotp

def _save_qr_from_path(crypto, qr_folder, platform, qr_path):
    with open(qr_path, 'rb') as f:
        original_data = f.read()
    uri = utils.read_qr_from_bytes(original_data)
    if not uri: return None, "Could not read QR code from image"
    secret = utils.extract_secret_from_uri(uri)
    _, _, username_from_uri = utils.clean_uri(uri)
    enc_img_data = crypto.encrypt_bytes(original_data)
    enc_img_path = os.path.join(qr_folder, f"{hashlib.md5(f'{platform}{time.time()}'.encode()).hexdigest()}.enc")
    open(enc_img_path, 'wb').write(enc_img_data)
    return (secret, username_from_uri, enc_img_path), None

def _save_qr_from_secret(crypto, qr_folder, platform, username, secret):
    try:
        secret = secret.replace(" ", "").upper()
        pyotp.TOTP(secret).now()
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=platform)
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        enc_img_data = crypto.encrypt_bytes(img_byte_arr.getvalue())
        enc_img_path = os.path.join(qr_folder, f"{hashlib.md5(f'{platform}{time.time()}'.encode()).hexdigest()}.enc")
        open(enc_img_path, 'wb').write(enc_img_data)
        return (secret, None, enc_img_path), None
    except Exception as e:
        return None, f"Error generating QR: {e}"

def add_credential(platform, username=None, secret=None, qr_path=None, key=None):
    crypto = aes.Crypto(key)
    qr_folder = os.path.join(config.APP_FOLDER, "qrs")
    os.makedirs(qr_folder, exist_ok=True)
    
    enc_img_path = None
    
    if qr_path and os.path.exists(qr_path):
        result, err = _save_qr_from_path(crypto, qr_folder, platform, qr_path)
        if err: return False, err
        secret, username_from_uri, enc_img_path = result
        username = username or username_from_uri
    elif secret and username:
        result, err = _save_qr_from_secret(crypto, qr_folder, platform, username, secret)
        if err: return False, err
        secret, _, enc_img_path = result
    else:
        return False, "Provide either a QR code or Secret Key + Username"
    
    cred_id = utils.generate_id(platform, secret)
    new_cred = {"id": cred_id, "platform": platform, "username": username, "secretcode": secret}
    if enc_img_path: utils.save_image_path(cred_id, enc_img_path)
    
    all_creds = utils.decode_encrypted_file()
    all_creds.append(new_cred)
    utils.save_otps_encrypted(all_creds, key)
    return True, "Credential added successfully"

def edit_credentials_full_ui(root, build_main_ui_callback):
    for w in root.winfo_children(): w.destroy()
    
    frame = ctk.CTkFrame(root, fg_color="#1e1e1e", corner_radius=0)
    frame.pack(expand=True, fill="both", padx=10, pady=10)
    root.unbind_all("<Return>")
    root.unbind_all("<Escape>")
    
    ctk.CTkLabel(frame, text="➕ Add New Credential", font=("Segoe UI", 16, "bold"), text_color="white").pack(pady=(5, 8))
    
    ctk.CTkLabel(frame, text="Platform Name:", text_color="white", font=("Segoe UI", 11, "bold")).pack(anchor="w")
    platform_entry = ctk.CTkEntry(frame, font=("Segoe UI", 11), height=32)
    platform_entry.pack(fill="x", pady=(0, 6))
    
    sep_frame = ctk.CTkFrame(frame, height=1, fg_color="#444")
    sep_frame.pack(fill="x", pady=6)
    
    ctk.CTkLabel(frame, text="📋 Option 1: Manual Entry", font=("Segoe UI", 11, "bold"), text_color="#ffcc00").pack(anchor="w", pady=(6, 2))
    
    ctk.CTkLabel(frame, text="Username:", text_color="white", font=("Segoe UI", 10)).pack(anchor="w")
    user_entry = ctk.CTkEntry(frame, font=("Segoe UI", 11), height=32)
    user_entry.pack(fill="x", pady=(0, 4))
    
    ctk.CTkLabel(frame, text="Secret Key:", text_color="white", font=("Segoe UI", 10)).pack(anchor="w")
    secret_entry = ctk.CTkEntry(frame, font=("Segoe UI", 11), height=32)
    secret_entry.pack(fill="x", pady=(0, 6))
    
    sep_frame2 = ctk.CTkFrame(frame, height=1, fg_color="#444")
    sep_frame2.pack(fill="x", pady=6)
    
    ctk.CTkLabel(frame, text="🖼️  Option 2: QR Code", font=("Segoe UI", 11, "bold"), text_color="#ffcc00").pack(anchor="w", pady=(6, 2))
    
    path_frame = ctk.CTkFrame(frame, fg_color="transparent")
    path_frame.pack(fill="x", pady=(0, 6))
    
    path_entry = ctk.CTkEntry(path_frame, font=("Segoe UI", 11), height=32)
    path_entry.pack(side="left", fill="x", expand=True)
    ctk.CTkButton(path_frame, text="Browse", width=70, height=32, command=lambda: (filename := filedialog.askopenfilename(title="Select QR Code", filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")])) and (path_entry.delete(0, tk.END), path_entry.insert(0, filename)), fg_color="#444", text_color="white", hover_color="#555", font=("Segoe UI", 10)).pack(side="right", padx=(8, 0))
    
    info_label = ctk.CTkLabel(frame, text="⚠️ Choose either manual entry (Username + Secret) or upload a QR code", font=("Segoe UI", 12), text_color="#888")
    info_label.pack(pady=4)
    
    def show_toast(msg, err=False):
        if config.toast_label: config.toast_label.destroy()
        config.toast_label = ctk.CTkLabel(root, text=msg, fg_color="#ff4d4d" if err else "#22cc22", text_color="white", font=("Segoe UI", 12), corner_radius=10, padx=16, pady=12)
        config.toast_label.place(relx=0.5, rely=0.95, anchor='s')
        root.after(2500, lambda: config.toast_label.destroy() if config.toast_label else None)
    
    def go_back():
        new_entries = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
        build_main_ui_callback(root, new_entries)
    
    def save_cred():
        platform = platform_entry.get().strip()
        username = user_entry.get().strip()
        secret = secret_entry.get().strip()
        qr_path = path_entry.get().strip()
        
        if not platform:
            show_toast("❌ Platform name is required", err=True)
            return
        
        # Check if user provided either manual entry or QR
        has_manual = username and secret
        has_qr = qr_path and os.path.exists(qr_path)
        
        if not has_manual and not has_qr:
            show_toast("❌ Provide either manual entry (Username + Secret) OR a QR code", err=True)
            return
        
        # If both provided, use QR only (QR takes priority)
        if has_qr:
            success, msg = add_credential(platform, None, None, qr_path, config.decrypt_key)
        else:
            success, msg = add_credential(platform, username, secret, None, config.decrypt_key)
        
        (show_toast("✅ " + msg), root.after(1500, go_back)) if success else show_toast("❌ " + msg, err=True)
    
    btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
    btn_frame.pack(pady=8)
    
    ctk.CTkButton(btn_frame, text="✅ Save", height=36, command=save_cred, fg_color="#444", text_color="white", hover_color="#666", font=("Segoe UI", 11, "bold"), width=110).pack(side="left", padx=4)
    ctk.CTkButton(btn_frame, text="❌ Cancel", height=36, command=go_back, fg_color="#3d3d3d", text_color="white", hover_color="#4d4d4d", font=("Segoe UI", 11, "bold"), width=110).pack(side="left", padx=4)
    
    platform_entry.focus()
    
    safe_trigger = lambda check, fn: fn() if all(w.winfo_exists() for w in check) else None
    root.bind("<Return>", lambda _: safe_trigger([platform_entry, user_entry, secret_entry, path_entry], save_cred))
    root.bind("<Escape>", lambda _: safe_trigger([frame], go_back))

def show_delete_confirmation_screen(root, cred, otp_entries, build_main_ui_callback):
    for w in root.winfo_children(): w.destroy()
    root.unbind_all("<Return>")
    root.unbind_all("<Escape>")
    
    cred_id, display_name, username = cred.get('id'), cred.get('platform', 'Unknown'), cred.get('username', 'Unknown')
    trunc_name, trunc_user = utils.truncate_platform_name(display_name), utils.truncate_username(username)
    
    frame = ctk.CTkFrame(root, fg_color="#1e1e1e", corner_radius=0)
    frame.pack(expand=True, fill="both", padx=40, pady=40)
    
    content_frame = ctk.CTkFrame(frame, fg_color="transparent")
    content_frame.pack(expand=True)
    
    ctk.CTkLabel(content_frame, text="⚠️", font=("Segoe UI", 80), text_color="#ff6b6b").pack(pady=(0, 15))
    ctk.CTkLabel(content_frame, text="Delete Credential?", font=("Segoe UI", 32, "bold"), text_color="#ff6b6b").pack(pady=(0, 10))
    ctk.CTkFrame(content_frame, height=2, fg_color="#444").pack(fill="x", pady=20)
    
    name_frame = ctk.CTkFrame(content_frame, fg_color="#2b2b2b", corner_radius=8)
    name_frame.pack(fill="x", pady=(0, 30), padx=20)
    ctk.CTkLabel(name_frame, text="Credential to Delete:", font=("Segoe UI", 11, "bold"), text_color="#aaaaaa").pack(anchor="w", padx=15, pady=(10, 5))
    ctk.CTkLabel(name_frame, text=trunc_name, font=("Segoe UI", 16, "bold"), text_color="#ffaa00").pack(anchor="w", padx=15, pady=(0, 5))
    ctk.CTkLabel(name_frame, text=f"Username: {trunc_user}", font=("Segoe UI", 12), text_color="#cccccc").pack(anchor="w", padx=15, pady=(0, 10))
    ctk.CTkLabel(content_frame, text="⚠️  This action cannot be undone.", font=("Segoe UI", 13), text_color="#ff8866").pack(pady=(0, 20))
    
    btn_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
    btn_frame.pack(pady=10)
    
    def perform_delete():
        if utils.delete_credential(cred_id, config.decrypt_key):
            otp_entries[:] = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
            build_main_ui_callback(root, otp_entries)
    
    def cancel_delete():
        build_main_ui_callback(root, otp_entries)
    
    ctk.CTkButton(btn_frame, text="🗑️  Delete", height=55, width=180, command=perform_delete, fg_color="#d32f2f", text_color="white", hover_color="#b71c1c", font=("Segoe UI", 14, "bold"), corner_radius=10).pack(side="left", padx=15)
    ctk.CTkButton(btn_frame, text="✖️  Cancel", height=55, width=180, command=cancel_delete, fg_color="#3d3d3d", text_color="white", hover_color="#4d4d4d", font=("Segoe UI", 14, "bold"), corner_radius=10).pack(side="left", padx=15)
    
    hint_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
    hint_frame.pack(pady=30)
    ctk.CTkLabel(hint_frame, text="⌨️  Keyboard Shortcuts:", font=("Segoe UI", 11, "bold"), text_color="#888").pack()
    ctk.CTkLabel(hint_frame, text="ENTER to Delete  •  ESC to Cancel", font=("Segoe UI", 10), text_color="#666").pack()
    
    ctk.CTkFrame(frame, fg_color="transparent").pack(expand=True)
    
    safe_trigger = lambda check, fn: fn() if all(w.winfo_exists() for w in check) else None
    root.bind("<Return>", lambda _: safe_trigger([content_frame], perform_delete))
    root.bind("<Escape>", lambda _: safe_trigger([content_frame], cancel_delete))
