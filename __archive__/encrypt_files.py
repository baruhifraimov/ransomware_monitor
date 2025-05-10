"""
File Encryption Utility

Purpose:
This script encrypts all .txt files within a specified folder. It uses Fernet
symmetric encryption from the 'cryptography' library. For each .txt file, it
creates an encrypted version with a .enc extension and then deletes the original
.txt file.

A unique encryption key is generated if one doesn't already exist (encryption_key.key).
This key is essential for decryption.

How to Run:
1. Ensure you have Python installed.
2. Install the 'cryptography' library: pip install cryptography
3. Navigate to the script's directory in your terminal.
4. Run the script using the command: python encrypt_files.py
5. When prompted, enter the full path to the folder containing the .txt files
   you wish to encrypt.
   Example: /Users/yourusername/Documents/MyTextFiles

IMPORTANT:
- Securely back up the 'encryption_key.key' file. If this key is lost, your
  encrypted files CANNOT be recovered.
- This script will delete the original .txt files after encryption.

Dependencies:
- cryptography library
"""

import os
from cryptography.fernet import Fernet

def generate_key():
    """Generates a key and saves it into a file."""
    key = Fernet.generate_key()
    with open("encryption_key.key", "wb") as key_file:
        key_file.write(key)
    print("Encryption key generated and saved to encryption_key.key")
    return key

def load_key():
    """Loads the previously generated key."""
    try:
        return open("encryption_key.key", "rb").read()
    except FileNotFoundError:
        print("Encryption key not found. Generate a new key or place encryption_key.key in the script's directory.")
        return None

def encrypt_file(file_path, key):
    """Encrypts a file and overwrites the original content."""
    f = Fernet(key)
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()
        
        encrypted_data = f.encrypt(file_data)
        
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, "wb") as file:
            file.write(encrypted_data)
        
        os.remove(file_path) # Remove original file after encryption
        print(f"Encrypted: {file_path} -> {encrypted_file_path}")
    except Exception as e:
        print(f"Failed to encrypt {file_path}: {e}")

def encrypt_folder_txt_files(folder_path, key):
    """Encrypts all .txt files in the specified folder."""
    if not os.path.isdir(folder_path):
        print(f"Error: Folder not found at {folder_path}")
        return

    for root, _, files in os.walk(folder_path):
        for filename in files:
            if filename.endswith(".txt"):
                file_path = os.path.join(root, filename)
                encrypt_file(file_path, key)

if __name__ == "__main__":
    folder_to_encrypt = input("Enter the full path of the folder containing .txt files to encrypt: ")
    
    # For simplicity, we'll try to load a key. If not found, generate a new one.
    # In a real application, key management needs careful consideration.
    encryption_key = load_key()
    if encryption_key is None:
        encryption_key = generate_key()

    if encryption_key:
        encrypt_folder_txt_files(folder_to_encrypt, encryption_key)
        print("\nEncryption process finished.")
        print("IMPORTANT: Keep the 'encryption_key.key' file safe. You will need it to decrypt your files.")
    else:
        print("Could not proceed without an encryption key.")
