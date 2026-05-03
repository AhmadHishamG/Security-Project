import os
import tkinter as tk
from tkinter import messagebox, simpledialog

from password_manager import (
    DiffieHellman,
    ElGamal,
    Vault,
    create_vault_export_package,
    import_vault_export_package,
    load_dh_parameters,
    sign_dh_public_key,
    unlock_or_create_user,
    verify_with_public_key,
)


class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("460x320")
        self.vault = None

        self.login_frame = tk.Frame(root, padx=24, pady=24)
        self.login_frame.pack(fill="both", expand=True)

        tk.Label(
            self.login_frame,
            text="Secure Password Manager",
            font=("Arial", 16, "bold"),
        ).pack(pady=(0, 18))

        tk.Label(self.login_frame, text="Username").pack(anchor="w")
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.pack(fill="x", pady=(0, 10))

        tk.Label(self.login_frame, text="Key Protection Password").pack(anchor="w")
        self.key_password_entry = tk.Entry(self.login_frame, show="*")
        self.key_password_entry.pack(fill="x", pady=(0, 16))

        tk.Button(
            self.login_frame,
            text="Login / Create User",
            command=self.login,
        ).pack(fill="x")

    def login(self):
        username = self.username_entry.get().strip()
        key_password = self.key_password_entry.get()

        if not username or not key_password:
            messagebox.showerror("Error", "Enter username and key password.")
            return

        vault = Vault(username)

        if not os.path.exists(vault.keys_file):
            vault.init_user(key_password)
            messagebox.showinfo("Created", f"New user created for {username}.")
        elif not vault.load_keys(key_password):
            messagebox.showerror("Error", "Incorrect key protection password.")
            return

        self.vault = vault
        self.show_main_menu()

    def show_main_menu(self):
        self.login_frame.destroy()

        frame = tk.Frame(self.root, padx=24, pady=24)
        frame.pack(fill="both", expand=True)

        tk.Label(
            frame,
            text=f"Logged in as {self.vault.username}",
            font=("Arial", 14, "bold"),
        ).pack(pady=(0, 14))

        buttons = [
            ("Add Credential", self.add_credential),
            ("Retrieve Credential", self.retrieve_credential),
            ("Update Credential", self.update_credential),
            ("Delete Credential", self.delete_credential),
            ("Export Vault", self.export_vault),
            ("Export Public Key", self.export_public_key),
        ]

        for text, command in buttons:
            tk.Button(frame, text=text, command=command).pack(fill="x", pady=4)

    def ask_master_password(self):
        return simpledialog.askstring(
            "Master Password",
            "Enter master password:",
            show="*",
            parent=self.root,
        )

    def load_credentials_from_prompt(self):
        master_password = self.ask_master_password()
        if master_password is None:
            return None, None

        credentials = self.vault.load_vault(master_password)
        if credentials is None:
            messagebox.showerror("Error", "Could not open vault.")
            return None, None

        return master_password, credentials

    def add_credential(self):
        master_password, credentials = self.load_credentials_from_prompt()
        if credentials is None:
            return

        site = simpledialog.askstring("Website", "Website:", parent=self.root)
        username = simpledialog.askstring("Username", "Username:", parent=self.root)
        password = simpledialog.askstring(
            "Password", "Password:", show="*", parent=self.root
        )

        if not site or not username or password is None:
            messagebox.showerror("Error", "All fields are required.")
            return

        credentials[site] = {"username": username, "password": password}
        self.vault.save_vault(master_password, credentials)
        messagebox.showinfo("Saved", "Credential saved and vault re-signed.")

    def choose_site(self, credentials, allow_whole_vault=False):
        if not credentials:
            messagebox.showinfo("Empty", "Vault is empty.")
            return None

        sites = list(credentials.keys())
        site_list = "\n".join(f"{index + 1}. {site}" for index, site in enumerate(sites))
        whole_vault_choice = len(sites) + 1
        if allow_whole_vault:
            site_list = f"{site_list}\n{whole_vault_choice}. Whole vault"

        choice = simpledialog.askinteger(
            "Choose Site",
            f"{site_list}\n\nEnter site number:",
            parent=self.root,
        )

        if choice is None:
            return None
        if allow_whole_vault and choice == whole_vault_choice:
            return "whole_vault"
        if choice < 1 or choice > len(sites):
            messagebox.showerror("Error", "Invalid site number.")
            return None

        return sites[choice - 1]

    def retrieve_credential(self):
        _, credentials = self.load_credentials_from_prompt()
        if credentials is None:
            return

        site = self.choose_site(credentials, allow_whole_vault=True)
        if site is None:
            return
        if site == "whole_vault":
            vault_text = []
            for stored_site, data in credentials.items():
                vault_text.append(
                    f"Site: {stored_site}\n"
                    f"Username: {data['username']}\n"
                    f"Password: {data['password']}"
                )
            messagebox.showinfo("Full Vault", "\n\n".join(vault_text))
            return

        data = credentials[site]
        messagebox.showinfo(
            "Credential",
            f"Site: {site}\nUsername: {data['username']}\nPassword: {data['password']}",
        )

    def update_credential(self):
        master_password, credentials = self.load_credentials_from_prompt()
        if credentials is None:
            return

        site = self.choose_site(credentials)
        if site is None:
            return

        old_data = credentials[site]
        new_username = simpledialog.askstring(
            "Update Username",
            "New username:",
            initialvalue=old_data["username"],
            parent=self.root,
        )
        new_password = simpledialog.askstring(
            "Update Password",
            "New password:",
            show="*",
            parent=self.root,
        )

        credentials[site] = {
            "username": new_username or old_data["username"],
            "password": new_password or old_data["password"],
        }
        self.vault.save_vault(master_password, credentials)
        messagebox.showinfo("Updated", "Credential updated and vault re-signed.")

    def delete_credential(self):
        master_password, credentials = self.load_credentials_from_prompt()
        if credentials is None:
            return

        site = self.choose_site(credentials)
        if site is None:
            return

        if not messagebox.askyesno("Confirm Delete", f"Delete {site}?"):
            return

        del credentials[site]
        self.vault.save_vault(master_password, credentials)
        messagebox.showinfo("Deleted", "Credential deleted and vault re-signed.")

    def export_public_key(self):
        self.vault.export_public_key()
        messagebox.showinfo(
            "Exported",
            f"Public key exported to {self.vault.public_key_file}.",
        )

    def export_vault(self):
        sender_master_password = simpledialog.askstring(
            "Export Vault",
            "Sender master password:",
            show="*",
            parent=self.root,
        )
        if sender_master_password is None:
            return

        credentials = self.vault.load_vault(sender_master_password)
        if credentials is None:
            messagebox.showerror("Error", "Could not open sender vault.")
            return

        recipient_name = simpledialog.askstring(
            "Export Vault",
            "Recipient username/device name:",
            parent=self.root,
        )
        if not recipient_name:
            return
        if recipient_name == self.vault.username:
            messagebox.showerror("Error", "Recipient must be different from sender.")
            return

        recipient_key_password = simpledialog.askstring(
            "Export Vault",
            "Recipient key protection password:",
            show="*",
            parent=self.root,
        )
        if recipient_key_password is None:
            return

        recipient_vault = Vault(recipient_name)
        if not os.path.exists(recipient_vault.keys_file):
            recipient_vault.init_user(recipient_key_password)
        elif not recipient_vault.load_keys(recipient_key_password):
            messagebox.showerror("Error", "Incorrect recipient key password.")
            return

        recipient_master_password = simpledialog.askstring(
            "Export Vault",
            "Recipient master password for imported vault:",
            show="*",
            parent=self.root,
        )
        if recipient_master_password is None:
            return

        q, alpha = load_dh_parameters()
        sender_dh_private, sender_dh_public = DiffieHellman.generate_keypair(q, alpha)
        recipient_dh_private, recipient_dh_public = DiffieHellman.generate_keypair(
            q, alpha
        )

        sender_message, sender_dh_signature = sign_dh_public_key(
            self.vault, q, alpha, sender_dh_public
        )
        if not verify_with_public_key(
            sender_message, sender_dh_signature, self.vault.public_key_data()
        ):
            messagebox.showerror("Error", "Recipient rejected sender DH signature.")
            return

        recipient_message, recipient_dh_signature = sign_dh_public_key(
            recipient_vault, q, alpha, recipient_dh_public
        )
        if not verify_with_public_key(
            recipient_message, recipient_dh_signature, recipient_vault.public_key_data()
        ):
            messagebox.showerror("Error", "Sender rejected recipient DH signature.")
            return

        sender_session_key = DiffieHellman.compute_secret(
            recipient_dh_public, sender_dh_private, q
        )
        recipient_session_key = DiffieHellman.compute_secret(
            sender_dh_public, recipient_dh_private, q
        )
        if sender_session_key != recipient_session_key:
            messagebox.showerror("Error", "Shared secret mismatch.")
            return

        encrypted_export = self.vault._encrypt_data(credentials, sender_session_key)
        export_signature = ElGamal.sign(
            encrypted_export, self.vault.p, self.vault.g, self.vault.priv_key
        )
        package = create_vault_export_package(
            self.vault,
            recipient_vault,
            q,
            alpha,
            sender_dh_public,
            sender_dh_signature,
            recipient_dh_public,
            recipient_dh_signature,
            encrypted_export,
            export_signature,
        )

        package_file = (
            f"{self.vault.username}_to_{recipient_vault.username}_export_package.json"
        )
        with open(package_file, "w") as f:
            import json

            json.dump(package, f, indent=2)

        if not import_vault_export_package(
            recipient_vault, recipient_master_password, package, recipient_session_key
        ):
            messagebox.showerror("Error", "Import failed.")
            return

        messagebox.showinfo(
            "Export Complete",
            f"Export package saved as {package_file}.\n"
            f"Recipient vault saved as {recipient_vault.vault_file}.",
        )


def main():
    root = tk.Tk()
    PasswordManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
