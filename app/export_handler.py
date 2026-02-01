import os, csv, utils, customtkinter as ctk, config

def export_to_csv():
    if not (otps := utils.decode_encrypted_file()):
        return False, "No data to export"
    
    try:
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        if not os.path.exists(desktop_path):
            desktop_path = os.path.expanduser("~")
        
        filepath = os.path.join(desktop_path, "CipherAuth.csv")
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            csv.writer(f).writerows([["ID", "Platform", "Username", "Secret", "TOTP URL"]] + [[cred.get(k, '') for k in ['id', 'platform', 'username', 'secretcode', 'uri']] for cred in otps])
        
        location = "Desktop" if os.path.exists(os.path.join(os.path.expanduser("~"), "Desktop")) else "home directory"
        return True, f"✅ File saved to {location}"
    except Exception as e:
        return False, f"❌ {str(e)}"

def handle_download(root):
    success, msg = export_to_csv()
    color = "#ff4d4d" if not success else "#22cc22"
    if config.toast_label: config.toast_label.destroy()
    config.toast_label = ctk.CTkLabel(root, text=msg, fg_color=color, text_color="white", font=("Segoe UI", 14), corner_radius=10, padx=16, pady=12)
    config.toast_label.place(relx=0.5, rely=0.9, anchor='s')
    root.after(2500, lambda: config.toast_label.destroy() if config.toast_label else None)
