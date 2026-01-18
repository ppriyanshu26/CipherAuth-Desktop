import customtkinter as ctk
import hashlib, os, config, utils, aes

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
                        pass
            
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

def reset_password_full_ui(root, otp_entries, build_main_ui_callback):
    for widget in root.winfo_children():
        widget.destroy()
    
    frame = ctk.CTkFrame(root, fg_color="#1e1e1e", corner_radius=0)
    frame.pack(expand=True, fill="both")
    
    root.unbind_all("<Return>")
    root.unbind_all("<Escape>")

    def create_entry(label_text):
        ctk.CTkLabel(frame, text=label_text, text_color="white", font=("Segoe UI", 14, "bold")).pack(pady=(15, 5))
        entry = ctk.CTkEntry(frame, show="*", font=("Segoe UI", 14), justify="center", width=250, height=40)
        entry.pack()
        return entry

    ctk.CTkLabel(frame, text="🔐 Reset Password", font=("Segoe UI", 20, "bold"), text_color="white").pack(pady=(40, 30))

    current_entry = create_entry("Enter current password:")
    current_entry.focus_set()
    new_entry = create_entry("New password:")
    confirm_entry = create_entry("Confirm new password:")

    button_frame = ctk.CTkFrame(frame, fg_color="transparent")
    button_frame.pack(pady=30)

    def show_toast(message, is_error=False):
        if config.toast_label:
            config.toast_label.destroy()
        color = "#ff4d4d" if is_error else "#444"
        config.toast_label = ctk.CTkLabel(root, text=message, fg_color=color, text_color="white",
                               font=("Segoe UI", 14), corner_radius=10, padx=16, pady=12)
        config.toast_label.place(relx=0.5, rely=0.9, anchor='s')
        root.after(2500, lambda: config.toast_label.destroy() if config.toast_label else None)

    def perform_reset():
        stored_hash = utils.get_stored_password()
        current_pwd = current_entry.get()
        current_hash = hashlib.sha256(current_pwd.encode()).hexdigest()
        
        if current_hash != stored_hash:
            show_toast("❌ Incorrect current password", is_error=True)
        elif new_entry.get() != confirm_entry.get():
            show_toast("❌ New passwords do not match", is_error=True)
        elif len(new_entry.get()) < 8:
            show_toast("❌ Password too short (min 8 chars)", is_error=True)
        else:
            new_pwd = new_entry.get()
            if reencrypt_all_data(current_pwd, new_pwd):
                utils.save_password(new_pwd)
                config.decrypt_key = new_pwd
                otp_entries[:] = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
                show_toast("✅ Password reset successfully")
                root.after(1500, lambda: build_main_ui_callback(root, otp_entries))
            else:
                show_toast("❌ Failed to re-encrypt data", is_error=True)

    def go_back():
        otp_entries[:] = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
        build_main_ui_callback(root, otp_entries)

    reset_btn = ctk.CTkButton(button_frame, text="✅ Submit", command=perform_reset,
                          font=("Segoe UI", 13, "bold"), width=120, height=40, fg_color="#444")
    reset_btn.pack(side="left", padx=5)
    
    cancel_btn = ctk.CTkButton(button_frame, text="❌ Cancel", command=go_back,
                          font=("Segoe UI", 13, "bold"), width=120, height=40, fg_color="#3d3d3d")
    cancel_btn.pack(side="left", padx=5)

    def safe_perform_reset(event=None):
        try:
            if current_entry.winfo_exists() and new_entry.winfo_exists() and confirm_entry.winfo_exists():
                perform_reset()
        except Exception:
            pass
    
    def safe_go_back(event=None):
        try:
            if frame.winfo_exists():
                go_back()
        except Exception:
            pass
    
    root.bind("<Return>", safe_perform_reset)
    root.bind("<Escape>", safe_go_back)


def reset_password_popup(parent, root, otp_entries, build_main_ui_callback):
    reset_password_full_ui(root, otp_entries, build_main_ui_callback)
