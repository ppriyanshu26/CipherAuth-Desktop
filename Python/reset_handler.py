import tkinter as tk
import customtkinter as ctk
import hashlib
import os
import config
import utils
import aes

def reencrypt_all_data(old_key, new_key):
    if not os.path.exists(config.ENCODED_FILE):
        return True
    
    old_crypto = aes.Crypto(old_key)
    new_crypto = aes.Crypto(new_key)
    new_lines = []
    
    try:
        with open(config.ENCODED_FILE, 'r') as f:
            lines = f.readlines()
            
        for line in lines:
            line = line.strip()
            if not line: continue
            
            try:
                decrypted_line = old_crypto.decrypt_aes(line)
            except Exception:
                print("Warning: Could not decrypt a line during re-encryption. Skipping.")
                continue

            platform, uri, enc_img_path = None, None, None
            
            if '|' in decrypted_line:
                parts = decrypted_line.split('|')
                if len(parts) == 3:
                    platform, uri, enc_img_path = [p.strip() for p in parts]
            if '|' in decrypted_line:
                parts = decrypted_line.split('|')
                if len(parts) == 3:
                    platform, uri, enc_img_path = [p.strip() for p in parts]
            elif ': ' in decrypted_line:
                parts = decrypted_line.split(': ', 1)
                platform = parts[0].strip()
                enc_img_path = parts[1].strip()
                if os.path.exists(enc_img_path):
                    try:
                        with open(enc_img_path, 'rb') as f_img:
                            old_enc_data = f_img.read()
                        raw_img_data = old_crypto.decrypt_bytes(old_enc_data)
                        uri = utils.read_qr_from_bytes(raw_img_data)
                    except Exception as e:
                        print(f"Warning: Failed to recover URI from legacy image {enc_img_path}: {e}")
                        print(f"Warning: Failed to recover URI from legacy image {enc_img_path}: {e}")
            
            if not platform:
                continue

            if enc_img_path and enc_img_path != "NONE" and os.path.exists(enc_img_path):
                try:
                    with open(enc_img_path, 'rb') as img_f:
                        old_enc_data = img_f.read()
                    
                    raw_img_data = old_crypto.decrypt_bytes(old_enc_data)
                    new_enc_data = new_crypto.encrypt_bytes(raw_img_data)
                    
                    with open(enc_img_path, 'wb') as img_f:
                        img_f.write(new_enc_data)
                except Exception as e:
                    print(f"Warning: Failed to re-encrypt image {enc_img_path}: {e}")

            new_line_content = f"{platform}|{uri if uri else ''}|{enc_img_path if enc_img_path else 'NONE'}"
            new_line = new_crypto.encrypt_aes(new_line_content)
            new_lines.append(new_line)
            
        with open(config.ENCODED_FILE, 'w') as f:
            for nl in new_lines:
                f.write(nl + "\n")
        return True
    except Exception as e:
        print(f"Re-encryption failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def reset_password_popup(parent, root, otp_entries, build_main_ui_callback):
    parent.resizable(False, False)
    frame = ctk.CTkFrame(parent, fg_color="#1e1e1e", corner_radius=0)
    frame.pack(expand=True, fill="both")
    root.unbind_all("<Return>")

    def create_entry(label_text):
        ctk.CTkLabel(frame, text=label_text, text_color="white", font=("Segoe UI", 14, "bold")).pack(pady=(15, 5))
        entry = ctk.CTkEntry(frame, show="*", font=("Segoe UI", 14), justify="center", width=250, height=40)
        entry.pack()
        return entry

    current_entry = create_entry("Enter current password:")
    current_entry.focus_set()
    new_entry = create_entry("New password:")
    confirm_entry = create_entry("Confirm new password:")

    error_label = ctk.CTkLabel(frame, text="", text_color="red", font=("Segoe UI", 12))
    error_label.pack(pady=(15, 0))

    def perform_reset():
        stored_hash = utils.get_stored_password()
        current_pwd = current_entry.get()
        current_hash = hashlib.sha256(current_pwd.encode()).hexdigest()
        if current_hash != stored_hash:
            error_label.configure(text="Incorrect current password")
        elif new_entry.get() != confirm_entry.get():
            error_label.configure(text="New passwords do not match")
        elif len(new_entry.get()) < 8:
            error_label.configure(text="Password too short (min 8 chars)")
        else:
            new_pwd = new_entry.get()
            if reencrypt_all_data(current_pwd, new_pwd):
                utils.save_password(new_pwd)
                config.decrypt_key = new_pwd
                parent.destroy()
                otp_entries[:] = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
                build_main_ui_callback(root, otp_entries)
            else:
                error_label.configure(text="Failed to re-encrypt data")

    reset_btn = ctk.CTkButton(frame, text="Reset Password", command=perform_reset,
                          font=("Segoe UI", 14, "bold"), width=200, height=45)
    reset_btn.pack(pady=20)
    utils.bind_enter(root, reset_btn)
