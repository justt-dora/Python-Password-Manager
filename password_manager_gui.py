
import base64
import json
import secrets
import string
import tkinter as tk
from pathlib import Path
from tkinter import messagebox
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Store the Day 4 demonstration vault separately
BASE_DIR = Path(__file__).resolve().parent
DEMO_DIR = BASE_DIR / "day4-demo"
DEMO_DIR.mkdir(exist_ok=True)

SALT_FILE = DEMO_DIR / "vault.salt"
VAULT_FILE = DEMO_DIR / "vault.dat"

vault_data = {}
fernet = None


def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    return base64.urlsafe_b64encode(
        kdf.derive(master_password.encode("utf-8"))
    )


def save_vault():
    encrypted_data = fernet.encrypt(
        json.dumps(vault_data).encode("utf-8")
    )
    VAULT_FILE.write_bytes(encrypted_data)


def unlock_vault():
    global fernet, vault_data

    master_password = password_login.get()

    if not master_password:
        messagebox.showwarning(
            "Missing password",
            "Enter your master password."
        )
        return

    # Create a fresh demo vault only when neither file exists.
    salt_exists = SALT_FILE.exists()
    vault_exists = VAULT_FILE.exists()

    if not salt_exists and not vault_exists:
        try:
            salt = secrets.token_bytes(16)
            key = derive_key(master_password, salt)
            candidate = Fernet(key)

            encrypted_empty_vault = candidate.encrypt(
                json.dumps({}).encode("utf-8")
            )

            SALT_FILE.write_bytes(salt)
            VAULT_FILE.write_bytes(encrypted_empty_vault)

        except OSError as error:
            messagebox.showerror(
                "Setup failed",
                f"Could not create the demo vault: {error}"
            )
            return

    elif not salt_exists or not vault_exists:
        messagebox.showerror(
            "Vault files missing",
            "The salt or vault file is missing. "
            "No existing file was replaced."
        )
        return

    # Unlock the existing or newly created vault.
    try:
        salt = SALT_FILE.read_bytes()
        key = derive_key(master_password, salt)
        candidate = Fernet(key)

        decrypted = candidate.decrypt(VAULT_FILE.read_bytes())
        loaded_data = json.loads(decrypted.decode("utf-8"))

        if not isinstance(loaded_data, dict):
            raise ValueError("Invalid vault format.")

        for site, record in loaded_data.items():
            if (
                not isinstance(site, str)
                or not isinstance(record, dict)
                or not isinstance(record.get("username"), str)
                or not isinstance(record.get("password"), str)
            ):
                raise ValueError("Invalid account record.")

        fernet = candidate
        vault_data = loaded_data

    except (InvalidToken, ValueError, UnicodeDecodeError):
        messagebox.showerror(
            "Unlock failed",
            "Incorrect master password or invalid vault file."
        )
        return
    except (OSError, json.JSONDecodeError) as error:
        messagebox.showerror(
            "Vault error",
            f"Could not read the vault: {error}"
        )
        return

    login_frame.pack_forget()
    app_frame.pack(fill="both", expand=True)
    refresh_accounts()

    messagebox.showinfo(
        "Success",
        "Your encrypted demonstration vault is unlocked!"
    )


def refresh_accounts():
    search_term = search_entry.get().strip().lower()
    account_list.delete(0, tk.END)

    for site in sorted(vault_data):
        if search_term in site.lower():
            account_list.insert(tk.END, site)


def select_account(event=None):
    selection = account_list.curselection()
    if not selection:
        return

    site = account_list.get(selection[0])
    record = vault_data[site]

    website_entry.delete(0, tk.END)
    website_entry.insert(0, site)

    username_entry.delete(0, tk.END)
    username_entry.insert(0, record["username"])

    password_entry.delete(0, tk.END)
    password_entry.insert(0, record["password"])


def clear_fields():
    website_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    account_list.selection_clear(0, tk.END)


def add_account():
    site = website_entry.get().strip()
    username = username_entry.get().strip()
    password = password_entry.get()

    if not site or not username or not password:
        messagebox.showwarning(
            "Missing details",
            "Enter the website, username, and password."
        )
        return

    if site in vault_data:
        replace = messagebox.askyesno(
            "Account exists",
            "This website already exists. Replace its saved details?"
        )
        if not replace:
            return

    vault_data[site] = {
        "username": username,
        "password": password,
    }

    try:
        save_vault()
    except OSError as error:
        messagebox.showerror(
            "Save failed",
            f"Could not save the vault: {error}"
        )
        return

    refresh_accounts()
    clear_fields()
    messagebox.showinfo("Saved", "Account encrypted and saved.")


def delete_account():
    selection = account_list.curselection()
    site = (
        account_list.get(selection[0])
        if selection else website_entry.get().strip()
    )

    if site not in vault_data:
        messagebox.showwarning(
            "No selection", "Select a saved account first."
        )
        return

    if not messagebox.askyesno(
        "Confirm deletion", f"Delete the saved account for {site}?"
    ):
        return

    old_record = vault_data.pop(site)

    try:
        save_vault()
    except OSError as error:
        vault_data[site] = old_record
        messagebox.showerror("Save failed", str(error))
        return

    refresh_accounts()
    clear_fields()
    messagebox.showinfo("Deleted", "Account deleted from the vault.")


def generate_password():
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    generated = "".join(secrets.choice(alphabet) for _ in range(20))

    password_entry.delete(0, tk.END)
    password_entry.insert(0, generated)


def toggle_password():
    password_entry.config(
        show="" if show_password.get() else "*"
    )


# Main window
root = tk.Tk()
root.title("Password Manager")
root.geometry("650x650")
root.minsize(560, 580)

login_frame = tk.Frame(root, padx=25, pady=25)
tk.Label(
    login_frame, text="Password Manager",
    font=("Arial", 20, "bold")
).pack(pady=15)

tk.Label(login_frame, text="Enter your master password").pack()
password_login = tk.Entry(login_frame, show="*", width=35)
password_login.pack(pady=8)
password_login.bind("<Return>", lambda event: unlock_vault())

tk.Button(
    login_frame, text="Unlock Vault",
    command=unlock_vault
).pack(pady=10)

login_frame.pack(fill="both", expand=True)

# Account management screen
app_frame = tk.Frame(root, padx=20, pady=15)

tk.Label(
    app_frame, text="Your Encrypted Password Vault",
    font=("Arial", 16, "bold")
).pack(pady=8)

tk.Label(app_frame, text="Search by website").pack(anchor="w")
search_entry = tk.Entry(app_frame)
search_entry.pack(fill="x", pady=4)
search_entry.bind("<KeyRelease>", lambda event: refresh_accounts())

tk.Label(app_frame, text="Saved websites (select one to view)").pack(anchor="w")
account_list = tk.Listbox(app_frame, height=6)
account_list.pack(fill="x", pady=5)
account_list.bind("<<ListboxSelect>>", select_account)

tk.Label(app_frame, text="Website").pack(anchor="w")
website_entry = tk.Entry(app_frame)
website_entry.pack(fill="x", pady=3)

tk.Label(app_frame, text="Username").pack(anchor="w")
username_entry = tk.Entry(app_frame)
username_entry.pack(fill="x", pady=3)

tk.Label(app_frame, text="Password").pack(anchor="w")
password_entry = tk.Entry(app_frame, show="*")
password_entry.pack(fill="x", pady=3)

show_password = tk.BooleanVar(value=False)
tk.Checkbutton(
    app_frame, text="Show password",
    variable=show_password, command=toggle_password
).pack(anchor="w")

button_frame = tk.Frame(app_frame)
button_frame.pack(pady=12)

tk.Button(
    button_frame, text="Add / Update",
    command=add_account
).grid(row=0, column=0, padx=4, pady=4)

tk.Button(
    button_frame, text="Delete",
    command=delete_account
).grid(row=0, column=1, padx=4, pady=4)

tk.Button(
    button_frame, text="Generate Password",
    command=generate_password
).grid(row=1, column=0, padx=4, pady=4)

tk.Button(
    button_frame, text="Clear Fields",
    command=clear_fields
).grid(row=1, column=1, padx=4, pady=4)

tk.Label(
    app_frame,
    text="Credentials are stored in the encrypted local vault.",
    fg="gray"
).pack(pady=5)

root.mainloop()
