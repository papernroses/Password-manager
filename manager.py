from cryptography.fernet import Fernet
import json
import os
import getpass
import string
import random
import hashlib

# ---------- CONFIG ----------
PASSWORD_FILE = "passwords.json"
KEY_FILE = "key.key"
MASTER_FILE = "master.key"

# ---------- KEY HANDLING ----------
def generate_key():
    """Generate encryption key if it doesn't exist"""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)

def load_key():
    return open(KEY_FILE, "rb").read()

generate_key()
key = load_key()
fernet = Fernet(key)

# ---------- MASTER PASSWORD HANDLING ----------
def hash_password(password):
    """Hash master password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def set_master_password():
    """Set master password on first run"""
    if not os.path.exists(MASTER_FILE):
        while True:
            pw1 = getpass.getpass("Set a master password: ")
            pw2 = getpass.getpass("Confirm master password: ")
            if pw1 == pw2:
                hashed = hash_password(pw1)
                encrypted = fernet.encrypt(hashed.encode())
                with open(MASTER_FILE, "wb") as f:
                    f.write(encrypted)
                print("[+] Master password set successfully!")
                break
            else:
                print("[-] Passwords do not match. Try again.")

def check_master_password():
    """Verify entered master password, set it on first run"""
    if not os.path.exists(MASTER_FILE):
        print("[*] No master password found. Let's set one up.")
        set_master_password()

    encrypted = open(MASTER_FILE, "rb").read()
    try:
        hashed_master = fernet.decrypt(encrypted).decode()
    except:
        print("[-] master.key is corrupted. Recreating...")
        os.remove(MASTER_FILE)
        set_master_password()
        encrypted = open(MASTER_FILE, "rb").read()
        hashed_master = fernet.decrypt(encrypted).decode()

    attempt = getpass.getpass("Enter master password: ")
    if hash_password(attempt) != hashed_master:
        print("[-] Incorrect master password. Exiting...")
        exit()
    print("[+] Access granted.")


# ---------- JSON HANDLING ----------
def load_passwords():
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                # If file is empty or invalid, return empty dict
                return {}
    return {}


def save_passwords(passwords):
    with open(PASSWORD_FILE, "w") as f:
        json.dump(passwords, f, indent=4)

# ---------- PASSWORD MANAGEMENT ----------
def add_password(account, password):
    passwords = load_passwords()
    encrypted_password = fernet.encrypt(password.encode()).decode()
    passwords[account] = encrypted_password
    save_passwords(passwords)
    print(f"[+] Password for '{account}' saved successfully!")

def get_password(account):
    passwords = load_passwords()
    encrypted_password = passwords.get(account)
    if encrypted_password:
        decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
        print(f"[+] Password for '{account}': {decrypted_password}")
    else:
        print(f"[-] No password found for '{account}'")

# ---------- PASSWORD GENERATOR ----------
def generate_strong_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

# ---------- CLI MENU ----------
def main():
    print("=== Welcome to Python CLI Password Manager ===")
    check_master_password()

    while True:
        print("\n--- Menu ---")
        print("1. Add Password")
        print("2. Get Password")
        print("3. Generate Strong Password")
        print("4. Exit")

        choice = input("Enter choice: ")

        if choice == "1":
            account = input("Enter account name: ")
            password = getpass.getpass("Enter password: ")
            add_password(account, password)

        elif choice == "2":
            account = input("Enter account name: ")
            get_password(account)

        elif choice == "3":
            length = input("Enter desired password length (default 12): ")
            length = int(length) if length.isdigit() else 12
            strong_pass = generate_strong_password(length)
            print(f"[+] Generated strong password: {strong_pass}")

        elif choice == "4":
            print("Exiting Password Manager. Goodbye!")
            break

        else:
            print("[-] Invalid choice. Try again.")

if __name__ == "__main__":
    main()
