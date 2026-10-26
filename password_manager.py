
import base64
from cryptography.hazmat.primitives import hashes
import os
from pathlib import Path
import json
from getpass import getpass

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Ask for the master password without displaying it
master_password = getpass("Enter your master password: ")

# Generate a random salt
salt_file = Path("vault.salt")
vault_file = Path("vault.dat")

if salt_file.exists():
    salt = salt_file.read_bytes()
    print("Existing salt loaded successfully!")
else:
    salt = os.urandom(16)
    salt_file.write_bytes(salt)
    print("New salt generated and saved!")


# Create the key derivation function
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=600000,
)

# Derive an encryption key
key = base64.urlsafe_b64encode(
    kdf.derive(master_password.encode())
)

# Create the Fernet encryption tool
fernet = Fernet(key)

print("Encryption key derived successfully!")
print("Salt generated successfully!")
print("Fernet encryption tool is ready!")
# Derive the key again using the same password and salt
kdf_again = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=600000,
)

key_again = base64.urlsafe_b64encode(
    kdf_again.derive(master_password.encode())
)

print("Do both keys match?", key == key_again)

# Create an empty vault if one does not exist
if not vault_file.exists():
    empty_vault = {}

    vault_json = json.dumps(empty_vault).encode()

    encrypted_vault = fernet.encrypt(vault_json)

    vault_file.write_bytes(encrypted_vault)

    print("New encrypted vault created successfully!")
else:
    print("Vault file already exists. It was not overwritten.")
    
# Load and decrypt the vault
encrypted_vault = vault_file.read_bytes()

try:
    decrypted_vault = fernet.decrypt(encrypted_vault)
    vault_data = json.loads(decrypted_vault.decode())

    print("Vault decrypted successfully!")
    print("Vault data:", vault_data)

except Exception:
    print("Incorrect master password or invalid vault file.")
    raise SystemExit
    
    # Convert the updated vault to JSON
    updated_json = json.dumps(vault_data).encode()


except Exception:
    print("Could not decrypt the vault.")

# Test whether the vault rejects a wrong password
wrong_password = "DefinitelyWrongPassword456!"

wrong_kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=600000,
)

wrong_key = base64.urlsafe_b64encode(
    wrong_kdf.derive(wrong_password.encode())
)

wrong_fernet = Fernet(wrong_key)

try:
    wrong_fernet.decrypt(vault_file.read_bytes())
    print("Warning: The vault was decrypted with the test key.")
except Exception:
    print("Incorrect password rejected successfully!")



