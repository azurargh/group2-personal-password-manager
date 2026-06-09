import json
import os
import base64
from hashlib import sha256
import tkinter as tk
from tkinter import messagebox

# master key file and storage file
MASTER_KEY_FILE = "master.key"
PASSWORD_FILE = "passwords.json"


def derive_key(master_pw: str) -> bytes:
    return sha256(master_pw.encode()).digest()


def xor_encrypt(data: str, key: bytes) -> str:
    bdata = data.encode()
    key = (key * ((len(bdata) // len(key)) + 1))[: len(bdata)]
    encrypted = bytes(a ^ b for a, b in zip(bdata, key))
    return base64.b64encode(encrypted).decode()


def xor_decrypt(data_b64: str, key: bytes) -> str:
    encrypted = base64.b64decode(data_b64)
    key = (key * ((len(encrypted) // len(key)) + 1))[: len(encrypted)]
    bdata = bytes(a ^ b for a, b in zip(encrypted, key))
    return bdata.decode()


def load_passwords(master_key: bytes) -> list:
    if not os.path.exists(PASSWORD_FILE):
        return []
    with open(PASSWORD_FILE, "r") as f:
        raw = json.load(f)
    return [
        {
            "service": entry["service"],
            "username": entry["username"],
            "password": xor_decrypt(entry["password"], master_key),
        }
        for entry in raw
    ]


def save_passwords(passwords: list, master_key: bytes):
    data = [
        {
            "service": e["service"],
            "username": e["username"],
            "password": xor_encrypt(e["password"], master_key),
        }
        for e in passwords
    ]
    with open(PASSWORD_FILE, "w") as f:
        json.dump(data, f, indent=2)

# ===============
# ----- GUI -----
# ===============

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.withdraw()  # Main dashboard stays hidden initially
        self.passwords = []
        self.master_key = None
        self.ui_built = False

        self.show_login_window()

    def helper_center_window(self, win, width, height):
        self.root.update_idletasks()
        scr_w = win.winfo_screenwidth()
        scr_h = win.winfo_screenheight()
        x = (scr_w // 2) - (width // 2)
        y = (scr_h // 2) - (height // 2)
        win.geometry(f"{width}x{height}+{x}+{y}")

    def show_login_window(self):
        login_win = tk.Toplevel(self.root)
        login_win.title("Personal Password Manager")
        self.helper_center_window(login_win, 550, 185)

        is_setup = not os.path.exists(MASTER_KEY_FILE)
        msg = "Set Master Password (First Time):" if is_setup else "Enter Master Password:"

        tk.Label(login_win, text=msg, font=("Arial", 14)).pack(pady=(25, 5))

        pw_entry = tk.Entry(login_win, show="*", width=30, font=("Arial", 14))
        pw_entry.pack(pady=5)
        pw_entry.focus_set()

        def attempt_login():
            master_pw = pw_entry.get()
            if not master_pw:
                messagebox.showwarning("Oops", "Password cannot be empty!", parent=login_win)
                return

            self.master_key = derive_key(master_pw)

            if is_setup:
                with open(MASTER_KEY_FILE, "wb") as f:
                    f.write(self.master_key)
                messagebox.showinfo("Success", "Master key created successfully!", parent=login_win)

            try:
                self.passwords = load_passwords(self.master_key)
                login_win.destroy()
                self.show_main_ui()
            except Exception:
                messagebox.showerror("Access Denied", "Please Try Again.", parent=login_win)

        pw_entry.bind("<Return>", lambda event: attempt_login())
        tk.Button(login_win, text="Login", command=attempt_login, width=15, font=("Arial", 12)).pack(pady=15)
        login_win.protocol("WM_DELETE_WINDOW", self.root.destroy)

    def show_main_ui(self):
        self.root.deiconify()
        self.root.title("Personal Password Manager")

        # Expanded height slightly to perfectly contain the new Reset button layout
        self.helper_center_window(self.root, 550, 605)
        self.root.protocol("WM_DELETE_WINDOW", self.save_and_exit)

        # Only build the layout components the very first time logging in
        if not self.ui_built:
            self.setup_ui()
            self.ui_built = True

        self.refresh_list()

    def setup_ui(self):
        tk.Label(self.root, text="Saved Accounts:", font=("Arial", 14, "bold")).pack(pady=(20, 0))

        # Adjusted listbox padding for comfortable line spacing
        self.listbox = tk.Listbox(
            self.root,
            width=50,
            height=10,
            font=("Arial", 12),
            activestyle="none",
            selectbackground="#0078d7",
            selectforeground="white"
        )
        self.listbox.pack(pady=20, padx=40, ipady=8)

        # Dashboard Action Controls
        tk.Button(self.root, text="Add New Entry", command=self.add_entry, font=("Arial", 12)).pack(fill=tk.X, padx=50, pady=4)
        tk.Button(self.root, text="View Platform", command=self.get_entry, font=("Arial", 12)).pack(fill=tk.X, padx=50, pady=4)
        tk.Button(self.root, text="Update Platform", command=self.update_entry, font=("Arial", 12)).pack(fill=tk.X, padx=50, pady=4)
        tk.Button(self.root, text="Delete Platform", command=self.delete_entry, font=("Arial", 12)).pack(fill=tk.X, padx=50, pady=4)
        tk.Button(self.root, text="Reset Vault", command=self.reset_vault, fg="orange", font=("Arial", 12, "bold")).pack(fill=tk.X, padx=50, pady=4)

        tk.Button(self.root, text="Save & Exit", command=self.save_and_exit, fg="red", font=("Arial", 12, "bold")).pack(fill=tk.X, padx=50, pady=25)

    def refresh_list(self):
        self.listbox.delete(0, tk.END)
        for e in self.passwords:
            self.listbox.insert(tk.END, e["service"])

    def get_selected_entry(self):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("Oops", "Please click on a platform in the list first.")
            return None
        return self.passwords[selection[0]]

    def add_entry(self):
        add_win = tk.Toplevel(self.root)
        add_win.title("Add New Entry")
        self.helper_center_window(add_win, 500, 290)
        add_win.transient(self.root)
        add_win.grab_set()

        tk.Label(add_win, text="Platform Name:", font=("Arial", 12)).pack(pady=(15, 2))
        s_entry = tk.Entry(add_win, font=("Arial", 12), width=35)
        s_entry.pack(pady=2)
        s_entry.focus_set()

        tk.Label(add_win, text="Username/Email:", font=("Arial", 12)).pack(pady=(10, 2))
        u_entry = tk.Entry(add_win, font=("Arial", 12), width=35)
        u_entry.pack(pady=2)

        tk.Label(add_win, text="Password:", font=("Arial", 12)).pack(pady=(10, 2))
        p_entry = tk.Entry(add_win, show="*", font=("Arial", 12), width=35)
        p_entry.pack(pady=2)

        def save():
            s, u, p = s_entry.get().strip(), u_entry.get().strip(), p_entry.get()
            if not s or not p:
                messagebox.showwarning("Error", "Platform and Password fields are required.", parent=add_win)
                return
            self.passwords.append({"service": s, "username": u, "password": p})
            self.refresh_list()
            add_win.destroy()

        tk.Button(add_win, text="Save Entry", command=save, font=("Arial", 11, "bold"), width=15).pack(pady=20)

    def get_entry(self):
        entry = self.get_selected_entry()
        if not entry: return

        view_win = tk.Toplevel(self.root)
        view_win.title(f"Details: {entry['service']}")
        self.helper_center_window(view_win, 500, 190)
        view_win.transient(self.root)
        view_win.grab_set()

        tk.Label(view_win, text=f"Platform: {entry['service']}", font=("Arial", 14, "bold")).pack(pady=(25, 5), anchor=tk.CENTER)
        tk.Label(view_win, text=f"Username/Email: {entry['username']}", font=("Arial", 13)).pack(pady=4, anchor=tk.CENTER)
        tk.Label(view_win, text="Password:", font=("Arial", 13, "bold")).pack(pady=(10, 2), anchor=tk.CENTER)

        # Selectable text field centered directly underneath it
        pass_entry = tk.Entry(view_win, font=("Arial", 13), bd=0, bg=view_win.cget("bg"), justify="center")
        pass_entry.insert(0, entry['password'])
        pass_entry.configure(state="readonly")
        pass_entry.pack(pady=(0, 15), anchor=tk.CENTER)

    def update_entry(self):
        entry = self.get_selected_entry()
        if not entry: return

        up_win = tk.Toplevel(self.root)
        up_win.title("Update Entry")
        self.helper_center_window(up_win, 500, 260)
        up_win.transient(self.root)
        up_win.grab_set()

        tk.Label(up_win, text=f"Updating Platform: {entry['service']}\n(Leave blank to keep unchanged)", font=("Arial", 11, "italic")).pack(pady=(15, 10))

        tk.Label(up_win, text=f"New Username/Email (Current: {entry['username']}):", font=("Arial", 11)).pack(pady=2)
        u_entry = tk.Entry(up_win, font=("Arial", 12), width=35)
        u_entry.pack(pady=2)
        u_entry.focus_set()

        tk.Label(up_win, text="New Password:", font=("Arial", 11)).pack(pady=2)
        p_entry = tk.Entry(up_win, show="*", font=("Arial", 12), width=35)
        p_entry.pack(pady=2)

        def update():
            new_u, new_p = u_entry.get().strip(), p_entry.get()
            if new_u: entry["username"] = new_u
            if new_p: entry["password"] = new_p
            self.refresh_list()
            up_win.destroy()

        tk.Button(up_win, text="Apply Changes", command=update, font=("Arial", 11, "bold"), width=15).pack(pady=20)

    def delete_entry(self):
        entry = self.get_selected_entry()
        if not entry: return

        del_win = tk.Toplevel(self.root)
        del_win.title("Confirm Delete")
        self.helper_center_window(del_win, 450, 160)
        del_win.transient(self.root)
        del_win.grab_set()

        tk.Label(del_win,
                 text=f"Are you sure you want to permanently delete the\nrecord entry for '{entry['service']}'?",
                 font=("Arial", 12)).pack(pady=20)

        btn_frame = tk.Frame(del_win)
        btn_frame.pack()

        def confirm():
            self.passwords.remove(entry)
            self.refresh_list()
            del_win.destroy()

        tk.Button(btn_frame, text="Yes, Delete", command=confirm, fg="red", font=("Arial", 11, "bold"), width=12).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Cancel", command=del_win.destroy, font=("Arial", 11), width=12).pack(side=tk.LEFT, padx=10)

    def reset_vault(self):
        confirm_win = tk.Toplevel(self.root)
        confirm_win.title("WARNING!")
        self.helper_center_window(confirm_win, 480, 190)
        confirm_win.transient(self.root)
        confirm_win.grab_set()

        msg = "Resetting the vault will PERMANENTLY DELETE all\nyour stored passwords and master keys.\nThis cannot be undone.\n\nAre you sure you want to proceed?"
        tk.Label(confirm_win, text=msg, font=("Arial", 11, "bold"), fg="red").pack(pady=15)

        btn_frame = tk.Frame(confirm_win)
        btn_frame.pack()

        def wipe_everything():
            try:
                if os.path.exists(MASTER_KEY_FILE):
                    os.remove(MASTER_KEY_FILE)
                if os.path.exists(PASSWORD_FILE):
                    os.remove(PASSWORD_FILE)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete files: {e}", parent=confirm_win)
                return

            self.passwords = []
            self.master_key = None

            messagebox.showinfo("Reset Successful", "Vault cleared! The application will now restart.", parent=confirm_win)

            confirm_win.destroy()
            self.root.withdraw()

            self.ui_built = False

            for widget in self.root.winfo_children():
                widget.destroy()

            self.show_login_window()

        tk.Button(btn_frame, text="Yes, Wipe Everything", command=wipe_everything, fg="red", font=("Arial", 11, "bold"), width=18).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Cancel", command=confirm_win.destroy, font=("Arial", 11), width=12).pack(side=tk.LEFT, padx=10)

    def save_and_exit(self):
        if self.master_key:
            save_passwords(self.passwords, self.master_key)
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()

    try:
        from ctypes import windll

        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    app = PasswordManagerGUI(root)
    root.mainloop()
