import os, csv, utils, customtkinter as ctk, config

def export_to_csv():
    otps = utils.decode_encrypted_file()
    if not otps:
        return False, "No data to export"
    
    try:
        desktop = os.path.expanduser("~/Desktop")
        filepath = os.path.join(desktop, "CipherAuth.csv")
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Platform", "TOTP URL"])
            for platform, uri, _ in otps:
                writer.writerow([platform, uri])
                
        return True, f"✅ File saved to desktop"
    except Exception as e:
        return False, f"❌ {str(e)}"

def show_download_toast(root, message, is_error=False):
    if config.toast_label:
        config.toast_label.destroy()
    color = "#ff4d4d" if is_error else "#22cc22"
    config.toast_label = ctk.CTkLabel(root, text=message, fg_color=color, text_color="white",
                               font=("Segoe UI", 14), corner_radius=10, padx=16, pady=12)
    config.toast_label.place(relx=0.5, rely=0.9, anchor='s')
    root.after(2500, lambda: config.toast_label.destroy() if config.toast_label else None)

def handle_download(root):
    success, msg = export_to_csv()
    is_error = not success
    show_download_toast(root, msg, is_error=is_error)
