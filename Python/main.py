import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
import pyotp, sys, time, hashlib, ctypes, config
import utils, reset_handler, creds_handler, export_handler

if sys.platform == "win32":
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

def open_popup(func, title="Popup", size="370x300", *args, **kwargs):
    if config.popup_window is not None and config.popup_window.winfo_exists():
        config.popup_window.lift()          
        config.popup_window.focus_force()   
        return config.popup_window
    popup = ctk.CTkToplevel(root)
    config.popup_window = popup
    popup.title(title)
    popup.geometry(size)
    popup.configure(fg_color="#1e1e1e")
    popup.transient(root)
    popup.grab_set()
    root_x = root.winfo_x()
    root_y = root.winfo_y()
    root_w = root.winfo_width()
    root_h = root.winfo_height()
    win_w, win_h = map(int, size.split("x"))
    x = root_x + (root_w//2-win_w//2)
    y = root_y + (root_h//2-win_h//2)
    popup.geometry(f"{win_w}x{win_h}+{x}+{y}")

    def on_close():
        config.popup_window = None
        popup.destroy()
    popup.protocol("WM_DELETE_WINDOW", on_close)
    func(popup, *args, **kwargs)
    return popup

def lock_app(root, otp_entries):
    for widget in root.winfo_children():
        widget.destroy()
    build_lock_screen(root, otp_entries)

def render_otp_list(root, otp_entries, query=""):
    for widget in config.inner_frame.winfo_children():
        widget.destroy()
    config.frames.clear()
    
    query = query.lower().strip()
    filtered = [e for e in otp_entries if e[0].lower().startswith(query)] if query else otp_entries

    if not filtered:
        msg = "🔍 No matches found" if query else "⚠️ No OTPs Loaded"
        ctk.CTkLabel(config.inner_frame, text=msg, font=("Segoe UI", 14, "bold"),
                 text_color="#888" if query else "red").pack(pady=20)
    else:
        for display_name, uri, enc_img_path in filtered:
            cleaned_uri, issuer, username = utils.clean_uri(uri)
            totp_obj = pyotp.TOTP(pyotp.parse_uri(cleaned_uri).secret)

            card = ctk.CTkFrame(config.inner_frame, fg_color="#2b2b2b", corner_radius=10)
            card.pack(fill="x", padx=12, pady=10)

            header = ctk.CTkFrame(card, fg_color="transparent")
            header.pack(fill="x", padx=10, pady=(10, 0))

            ctk.CTkLabel(header, text=display_name, font=("Segoe UI", 14, "bold"), text_color="#ffffff").pack(side="left")
            delete_btn = ctk.CTkButton(header, text="Delete", width=60, height=24, font=("Segoe UI", 11), fg_color="transparent", text_color="#ff4d4d", hover_color="#3d3d3d")
            delete_btn.pack(side="right", padx=(5, 0))
            
            qr_toggle_btn = None
            if enc_img_path != "NONE":
                qr_toggle_btn = ctk.CTkButton(header, text="View QR", width=60, height=24, font=("Segoe UI", 11), fg_color="#444", text_color="white", hover_color="#555")
                qr_toggle_btn.pack(side="right")

            def confirm_delete(p=display_name, u=uri, path=enc_img_path):
                if messagebox.askyesno("Delete Credential", f"Are you sure you want to delete '{p}'?"):
                    if utils.delete_credential(p, u, config.decrypt_key, path):
                        otp_entries[:] = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
                        render_otp_list(root, otp_entries)
                    else:
                        messagebox.showerror("Error", "Failed to delete credential")

            delete_btn.configure(command=confirm_delete)
            ctk.CTkLabel(card, text=username, font=("Segoe UI", 11), text_color="#aaaaaa", anchor="w").pack(fill="x", padx=10)
            
            bottom = ctk.CTkFrame(card, fg_color="transparent")
            bottom.pack(fill="x", padx=10, pady=(5, 10))
            
            code_var = tk.StringVar()
            ctk.CTkLabel(bottom, textvariable=code_var, font=("Courier", 20, "bold"), text_color="#00ffcc").pack(side="left")
            
            time_var = tk.StringVar()
            time_label = ctk.CTkLabel(bottom, textvariable=time_var, font=("Segoe UI", 12, "bold"), text_color="#00ffcc")
            time_label.pack(side="left", padx=(10, 0))

            ctk.CTkButton(bottom, text="Copy", width=60, height=28, font=("Segoe UI", 11), fg_color="#444", text_color="white", hover_color="#666", command=lambda v=code_var: utils.copy_and_toast(v, root)).pack(side="right")

            if qr_toggle_btn:
                qr_frame = ctk.CTkFrame(card, fg_color="transparent")
                def toggle_qr(event=None, f=qr_frame, path=enc_img_path, btn=qr_toggle_btn):
                    if f.winfo_viewable():
                        f.pack_forget()
                        btn.configure(text="View QR")
                    else:
                        f.pack(fill="x", pady=(0, 10))
                        show_blurred_qr(f, path)
                        btn.configure(text="Hide QR")
                qr_toggle_btn.configure(command=toggle_qr)

                def show_blurred_qr(f, path):
                    for w in f.winfo_children(): w.destroy()
                    img_pil = utils.get_qr_image(path, config.decrypt_key, blur=True)
                    if img_pil:
                        img_ctk = ctk.CTkImage(light_image=img_pil, dark_image=img_pil, size=(200, 200))
                        lbl = ctk.CTkLabel(f, image=img_ctk, text="", cursor="hand2")
                        lbl.image = img_ctk
                        lbl.is_revealed = False
                        lbl.pack()
                        hint = ctk.CTkLabel(f, text="Tap to unblur QR", font=("Segoe UI", 12, "italic"), text_color="#888888")
                        hint.pack(pady=(2, 0))
                        def on_click(e, p=path, l=lbl, h=hint):
                            if not l.is_revealed:
                                reveal_qr(l, p, h)
                            else:
                                blur_qr(l, p, h)
                        lbl.bind("<Button-1>", on_click)

                def reveal_qr(label, path, hint):
                    img_pil = utils.get_qr_image(path, config.decrypt_key, blur=False)
                    if img_pil:
                        img_ctk = ctk.CTkImage(light_image=img_pil, dark_image=img_pil, size=(200, 200))
                        label.configure(image=img_ctk)
                        label.image = img_ctk
                        label.is_revealed = True
                        hint.configure(text="Tap to blur QR")

                def blur_qr(label, path, hint):
                    img_pil = utils.get_qr_image(path, config.decrypt_key, blur=True)
                    if img_pil:
                        img_ctk = ctk.CTkImage(light_image=img_pil, dark_image=img_pil, size=(200, 200))
                        label.configure(image=img_ctk)
                        label.image = img_ctk
                        label.is_revealed = False
                        hint.configure(text="Tap to unblur QR")

            config.frames.append({"totp": totp_obj, "code_var": code_var, "time_var": time_var, "time_label": time_label})

def build_main_ui(root, otp_entries):
    for widget in root.winfo_children():
        widget.destroy()

    top_bar = ctk.CTkFrame(root, fg_color="#1e1e1e", corner_radius=0)
    top_bar.pack(side="top", fill="x", padx=10)

    search_entry = ctk.CTkEntry(top_bar, font=("Segoe UI", 13), placeholder_text="Type to search", height=35, placeholder_text_color="#888")
    search_entry.pack(side="left", fill="x", expand=True, padx=(0, 10), pady=10)
    
    def on_search_change(event=None):
        query = search_entry.get()
        render_otp_list(root, otp_entries, query)
    
    search_entry.bind("<KeyRelease>", on_search_change)

    lock_btn = ctk.CTkButton(top_bar, text="🔒 Lock", width=80, height=35, font=("Segoe UI", 12, "bold"),
                     fg_color="#444", text_color="white", hover_color="#666",
                     command=lambda: lock_app(root, otp_entries))
    lock_btn.pack(side="right", pady=10)

    ctk.CTkFrame(root, height=2, fg_color="#333").pack(fill="x")

    outer_frame = ctk.CTkFrame(root, fg_color="#1e1e1e", corner_radius=0)
    outer_frame.pack(fill="both", expand=True)

    footer = ctk.CTkFrame(outer_frame, fg_color="#1e1e1e", corner_radius=0)
    footer.pack(side="bottom", fill="x")

    ctk.CTkButton(footer, text="🔄 Reset", font=("Segoe UI", 12),
              fg_color="#2b2b2b", text_color="white", hover_color="#3d3d3d", height=45, corner_radius=0,
              command=lambda: reset_handler.reset_password_full_ui(root, otp_entries, build_main_ui)).pack(side="left", fill="x", expand=True)

    ctk.CTkButton(footer, text="➕ Add Creds", font=("Segoe UI", 12),
              fg_color="#2b2b2b", text_color="white", hover_color="#3d3d3d", height=45, corner_radius=0,
              command=lambda: creds_handler.edit_credentials_full_ui(root, build_main_ui)).pack(side="left", fill="x", expand=True)

    ctk.CTkButton(footer, text="📥 Download", font=("Segoe UI", 12),
              fg_color="#2b2b2b", text_color="white", hover_color="#3d3d3d", height=45, corner_radius=0,
              command=lambda: export_handler.handle_download(root)).pack(side="left", fill="x", expand=True)

    config.inner_frame = ctk.CTkScrollableFrame(outer_frame, fg_color="#1e1e1e", corner_radius=0)
    config.inner_frame.pack(fill="both", expand=True)

    render_otp_list(root, otp_entries)

    if otp_entries:
        update_totps(root)

def update_totps(root):
    for entry in config.frames:
        totp, code_var, time_var, time_label = entry["totp"], entry["code_var"], entry["time_var"], entry["time_label"]
        code, time_left = totp.now(), 30 - int(time.time()) % 30
        try:
            code_var.set(code)
            time_var.set(f"{time_left}s")
            color = "#28db73" if time_left>20 else "#ffcc00" if time_left>10 else "#ff4d4d"
            time_label.configure(text_color=color)
        except (tk.TclError, ValueError): continue
    root.after(1000, lambda: update_totps(root))

def build_create_password_screen(root, otp_entries):
    frame = ctk.CTkFrame(root, fg_color="#1e1e1e"); frame.pack(expand=True, fill="both")
    root.unbind_all("<Return>")
    ctk.CTkLabel(frame, text="🔐 Create a Password", font=("Segoe UI",20,"bold"), text_color="white").pack(pady=(60,20))
    pwd1 = ctk.CTkEntry(frame, show="*", font=("Segoe UI",14), width=250, placeholder_text="Enter Password", height=40)
    pwd2 = ctk.CTkEntry(frame, show="*", font=("Segoe UI",14), width=250, placeholder_text="Confirm Password", height=40)
    pwd1.pack(pady=(10,10)); pwd2.pack(pady=(0,10))
    
    pwd1.focus()
    root.after(100, pwd1.focus)
    
    error_label = ctk.CTkLabel(frame, text="", text_color="red", font=("Segoe UI",12)); error_label.pack()

    def submit_password():
        if pwd1.get() != pwd2.get(): error_label.configure(text="Passwords do not match.")
        elif len(pwd1.get()) < 8: error_label.configure(text="Password too short (min 8 chars).")
        else: utils.save_password(pwd1.get()); frame.destroy(); build_lock_screen(root, otp_entries)

    submit_btn = ctk.CTkButton(frame, text="Save & Continue", font=("Segoe UI",14, "bold"),
                           width=250, height=45,
                           command=submit_password)
    submit_btn.pack(pady=20); utils.bind_enter(root, submit_btn)

def check_password(root, entry, error_label, otp_entries, lock_frame):
    stored_password = utils.get_stored_password()
    entered_password = entry.get()
    entered_hash = hashlib.sha256(entered_password.encode()).hexdigest()
    
    if entered_hash == stored_password:
        config.decrypt_key = entered_password
        lock_frame.destroy()
        
        otp_entries[:] = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
        build_main_ui(root, otp_entries)
    else:
        error_label.configure(text="❌ Incorrect password")

def build_lock_screen(root, otp_entries):
    frame = ctk.CTkFrame(root, fg_color="#1e1e1e"); frame.pack(expand=True, fill="both")
    root.unbind_all("<Return>")
    ctk.CTkLabel(frame, text="🔒 Enter Password", font=("Segoe UI",20,"bold"), text_color="white").pack(pady=(80,20))
    entry = ctk.CTkEntry(frame, show="*", font=("Segoe UI",14), width=250, placeholder_text="Password", height=40); entry.pack(pady=(0,10))
    
    entry.focus()
    root.after(100, entry.focus)
    
    error_label = ctk.CTkLabel(frame, text="", text_color="red", font=("Segoe UI",12)); error_label.pack()
    unlock_btn = ctk.CTkButton(frame, text="Unlock", font=("Segoe UI",14, "bold"),
                           width=250, height=45,
                           command=lambda: check_password(root, entry, error_label, otp_entries, frame))
    unlock_btn.pack(pady=20); utils.bind_enter(root, unlock_btn)

if __name__ == "__main__":
    root = ctk.CTk()
    root.title("CipherAuth")
    root.iconbitmap("icon.ico")
    root.geometry("420x550")
    root.configure(fg_color="#1e1e1e")
    root.resizable(False, False)

    otp_entries = []
    if utils.get_stored_password() is None:
        build_create_password_screen(root, otp_entries)
    else:
        build_lock_screen(root, otp_entries)

    root.mainloop()
