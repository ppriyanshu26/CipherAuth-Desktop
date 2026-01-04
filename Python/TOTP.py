import tkinter as tk
from tkinter import  messagebox
import pyotp
import time
import hashlib
import config
import utils
import reset_handler
import creds_handler
import export_handler

def open_popup(func, title="Popup", size="370x300", *args, **kwargs):
    if config.popup_window is not None and config.popup_window.winfo_exists():
        config.popup_window.lift()          
        config.popup_window.focus_force()   
        return config.popup_window
    popup = tk.Toplevel(root)
    config.popup_window = popup
    popup.title(title)
    popup.geometry(size)
    popup.configure(bg="#1e1e1e")
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
        tk.Label(config.inner_frame, text=msg, font=("Segoe UI", 11, "bold"),
                 fg="#888" if query else "red", bg="#1e1e1e").pack(pady=20)
    else:
        for display_name, uri, enc_img_path in filtered:
            cleaned_uri, issuer, username = utils.clean_uri(uri)
            totp_obj = pyotp.TOTP(pyotp.parse_uri(cleaned_uri).secret)

            card = tk.Frame(config.inner_frame, bg="#2b2b2b", padx=12, pady=12)
            card.pack(fill="x", padx=12, pady=10)

            header = tk.Frame(card, bg="#2b2b2b")
            header.pack(fill="x")

            tk.Label(header, text=display_name, font=("Segoe UI", 12, "bold"),bg="#2b2b2b", fg="#ffffff", anchor="w").pack(side="left")
            delete_btn = tk.Button(header, text="Delete", font=("Segoe UI", 8), bg="#2b2b2b", fg="#ff4d4d", relief="flat", padx=5, activebackground="#3d3d3d", activeforeground="#ff4d4d")
            delete_btn.pack(side="right", padx=(5, 0))
            
            qr_toggle_btn = None
            if enc_img_path != "NONE":
                qr_toggle_btn = tk.Button(header, text="View QR", font=("Segoe UI", 8), bg="#444", fg="white", relief="flat", padx=5)
                qr_toggle_btn.pack(side="right")

            def confirm_delete(p=display_name, u=uri, path=enc_img_path):
                if messagebox.askyesno("Delete Credential", f"Are you sure you want to delete '{p}'?"):
                    if utils.delete_credential(p, u, config.decrypt_key):
                        otp_entries[:] = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
                        render_otp_list(root, otp_entries)
                    else:
                        messagebox.showerror("Error", "Failed to delete credential")

            delete_btn.config(command=confirm_delete)
            tk.Label(card, text=username, font=("Segoe UI", 9),fg="#aaaaaa", bg="#2b2b2b", anchor="w").pack(fill="x")
            bottom = tk.Frame(card, bg="#2b2b2b")
            bottom.pack(fill="x", pady=(8, 0))
            code_var = tk.StringVar()
            tk.Label(bottom, textvariable=code_var, font=("Courier", 16, "bold"), bg="#2b2b2b", fg="#00ffcc").pack(side="left")
            time_var = tk.StringVar()
            time_label = tk.Label(bottom, textvariable=time_var, font=("Segoe UI", 10, "bold"), bg="#2b2b2b", fg="#00ffcc")
            time_label.pack(side="left", padx=(10, 0))

            tk.Button(bottom, text="Copy", font=("Segoe UI", 9), bg="#444", fg="white", activebackground="#666", relief="flat", command=lambda v=code_var: utils.copy_and_toast(v, root)).pack(side="right")

            if qr_toggle_btn:
                qr_frame = tk.Frame(card, bg="#2b2b2b")
                def toggle_qr(event=None, f=qr_frame, path=enc_img_path):
                    if f.winfo_viewable():
                        f.pack_forget()
                    else:
                        f.pack(fill="x", pady=(10, 0))
                        show_blurred_qr(f, path)
                qr_toggle_btn.config(command=toggle_qr)

                def show_blurred_qr(f, path):
                    for w in f.winfo_children(): w.destroy()
                    img_tk = utils.get_qr_image(path, config.decrypt_key, blur=True)
                    if img_tk:
                        lbl = tk.Label(f, image=img_tk, bg="#2b2b2b", cursor="hand2")
                        lbl.image = img_tk 
                        lbl.pack()
                        hint = tk.Label(f, text="Tap to view QR", font=("Segoe UI", 8, "italic"), bg="#2b2b2b", fg="#888888")
                        hint.pack(pady=(2, 0))
                        def on_click(e, p=path, l=lbl, h=hint):
                            reveal_qr(l, p)
                            h.destroy()
                        lbl.bind("<Button-1>", on_click)

                def reveal_qr(label, path):
                    img_tk = utils.get_qr_image(path, config.decrypt_key, blur=False)
                    if img_tk:
                        label.config(image=img_tk)
                        label.image = img_tk

            config.frames.append({"totp": totp_obj, "code_var": code_var, "time_var": time_var, "time_label": time_label})

def build_main_ui(root, otp_entries):
    for widget in root.winfo_children():
        widget.destroy()

    top_bar = tk.Frame(root, bg="#1e1e1e")
    top_bar.pack(side="top", fill="x", padx=10)

    search_var = tk.StringVar()
    search_entry = tk.Entry(top_bar, textvariable=search_var, font=("Segoe UI", 12), bg="#333", fg="#888", insertbackground="white", relief="flat")
    search_entry.insert(0, "Type to search")
    search_entry.pack(side="left", fill="x", expand=True, padx=(0, 10), pady=10, ipady=5)
    
    def on_focus_in(event):
        if search_var.get() == "Type to search":
            search_entry.delete(0, tk.END)
            search_entry.config(fg="white")

    def on_focus_out(event):
        if not search_var.get():
            search_entry.insert(0, "Type to search")
            search_entry.config(fg="#888")

    search_entry.bind("<FocusIn>", on_focus_in)
    search_entry.bind("<FocusOut>", on_focus_out)

    def on_search_change(*args):
        query = search_var.get()
        if query == "Type to search":
            query = ""
        render_otp_list(root, otp_entries, query)
    search_var.trace_add("write", on_search_change)

    lock_btn = tk.Button(top_bar, text="🔒 Lock", font=("Segoe UI", 9, "bold"),
                     bg="#444", fg="white", relief="flat", activebackground="#666",
                     command=lambda: lock_app(root, otp_entries))
    lock_btn.pack(side="right", pady=10)

    # Separator line
    tk.Frame(root, height=1, bg="#333").pack(fill="x")

    outer_frame = tk.Frame(root, bg="#1e1e1e")
    outer_frame.pack(fill="both", expand=True)

    # ---- FOOTER (pack first so it stays at bottom) ----
    footer = tk.Frame(outer_frame, bg="#1e1e1e")
    footer.pack(side="bottom", fill="x")

    tk.Button(footer, text="🔄 Reset", font=("Segoe UI", 10),
              bg="#2b2b2b", fg="white", relief="flat", height=2,
              command=lambda: open_popup(reset_handler.reset_password_popup, title="Reset Password", size="350x400", root=root)).pack(side="left", fill="x", expand=True)

    tk.Button(footer, text="➕ Edit Creds", font=("Segoe UI", 10),
              bg="#2b2b2b", fg="white", relief="flat", height=2,
              command=lambda: open_popup(creds_handler.edit_credentials_popup, title="Edit Credentials", size="350x450", root=root, build_main_ui_callback=build_main_ui)).pack(side="left", fill="x", expand=True)

    tk.Button(footer, text="📥 Download", font=("Segoe UI", 10),
              bg="#2b2b2b", fg="white", relief="flat", height=2,
              command=export_handler.handle_download).pack(side="left", fill="x", expand=True)

    # ---- SCROLLABLE AREA ----
    canvas_frame = tk.Frame(outer_frame, bg="#1e1e1e")
    canvas_frame.pack(side="top", fill="both", expand=True)

    config.canvas = tk.Canvas(canvas_frame, bg="#1e1e1e", highlightthickness=0, borderwidth=0)
    scrollbar = tk.Scrollbar(canvas_frame, orient="vertical", command=config.canvas.yview)
    config.canvas.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    config.canvas.pack(side="left", fill="both", expand=True)

    config.inner_frame = tk.Frame(config.canvas, bg="#1e1e1e")
    config.canvas.create_window((0, 0), window=config.inner_frame, anchor="nw", tags="inner_frame")
    config.inner_frame.bind("<Configure>", lambda e: config.canvas.configure(scrollregion=config.canvas.bbox("all")))
    config.canvas.bind("<Configure>", lambda e: config.canvas.itemconfig("inner_frame", width=e.width))
    config.canvas.bind_all("<MouseWheel>", utils.on_mousewheel)

    # Reset scroll position to top
    config.canvas.yview_moveto(0)

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
            time_label.configure(fg=color)
        except tk.TclError: continue
    root.after(1000, lambda: update_totps(root))

def build_create_password_screen(root, otp_entries):
    frame = tk.Frame(root, bg="#1e1e1e"); frame.pack(expand=True)
    root.unbind_all("<Return>")
    tk.Label(frame, text="🔐 Create a Password", font=("Segoe UI",14,"bold"), bg="#1e1e1e", fg="white").pack(pady=(40,10))
    pwd1, pwd2 = tk.Entry(frame, show="*", font=("Segoe UI",12), width=20, justify="center"), tk.Entry(frame, show="*", font=("Segoe UI",12), width=20, justify="center")
    pwd1.pack(pady=(10,5)); pwd1.focus(); pwd2.pack(pady=(0,10))
    error_label = tk.Label(frame, text="", fg="red", bg="#1e1e1e", font=("Segoe UI",9)); error_label.pack()

    def submit_password():
        if pwd1.get() != pwd2.get(): error_label.config(text="Passwords do not match.")
        elif len(pwd1.get()) < 4: error_label.config(text="Password too short (min 4 chars).")
        else: utils.save_password(pwd1.get()); frame.destroy(); build_lock_screen(root, otp_entries)

    submit_btn = tk.Button(frame, text="Save & Continue", font=("Segoe UI",10),
                           bg="#444", fg="white", relief="flat", activebackground="#666",
                           command=submit_password)
    submit_btn.pack(pady=10); utils.bind_enter(root, submit_btn)

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
        error_label.config(text="❌ Incorrect password")

def build_lock_screen(root, otp_entries):
    frame = tk.Frame(root, bg="#1e1e1e"); frame.pack(expand=True)
    root.unbind_all("<Return>")
    tk.Label(frame, text="🔒 Enter Password", font=("Segoe UI",14,"bold"), bg="#1e1e1e", fg="white").pack(pady=(30,10))
    entry = tk.Entry(frame, show="*", font=("Segoe UI",12), width=20, justify="center"); entry.pack(pady=(0,10)); entry.focus()
    error_label = tk.Label(frame, text="", fg="red", bg="#1e1e1e", font=("Segoe UI",9)); error_label.pack()
    unlock_btn = tk.Button(frame, text="Unlock", font=("Segoe UI",10),
                           bg="#444", fg="white", relief="flat", activebackground="#666",
                           command=lambda: check_password(root, entry, error_label, otp_entries, frame))
    unlock_btn.pack(pady=10); utils.bind_enter(root, unlock_btn)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("TOTP Authenticator v3.0.0")
    root.geometry("420x500")
    root.configure(bg="#1e1e1e")
    root.resizable(False, False)

    otp_entries = []
    if utils.get_stored_password() is None:
        build_create_password_screen(root, otp_entries)
    else:
        build_lock_screen(root, otp_entries)

    root.mainloop()
