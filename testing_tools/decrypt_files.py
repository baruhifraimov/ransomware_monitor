"""
File Decryption Utility

Purpose:
This script decrypts files in a specified folder that were previously encrypted
by the 'encrypt_files.py' script (i.e., files with a .enc extension).
It uses the Fernet symmetric encryption from the 'cryptography' library and
requires the 'encryption_key.key' file that was generated during the encryption
process.

For each .enc file, it creates a decrypted version (removing the .enc extension)
and then deletes the original .enc file.

How to Run:
1. Ensure you have Python installed.
2. Install the 'cryptography' library: pip install cryptography
3. Place the 'encryption_key.key' file in the same directory as this script.
4. Navigate to the script's directory in your terminal.
5. Run the script using the command: python decrypt_files.py
6. When prompted, enter the full path to the folder containing the .enc files
   you wish to decrypt.
   Example: /Users/yourusername/Documents/MyEncryptedFiles

IMPORTANT:
- The 'encryption_key.key' file MUST be present in the same directory as this
  script for decryption to work.
- This script will delete the original .enc files after successful decryption.

Dependencies:
- cryptography library
- encryption_key.key (must be in the same directory)
"""

import os
from cryptography.fernet import Fernet

def load_key():
    """Loads the encryption key from encryption_key.key."""
    try:
        return open("encryption_key.key", "rb").read()
    except FileNotFoundError:
        print("Error: encryption_key.key not found. This file is required for decryption.")
        print("Make sure encryption_key.key is in the same directory as this script.")
        return None

def decrypt_file(file_path, key):
    """Decrypts a file and overwrites the encrypted content."""
    f = Fernet(key)
    if not file_path.endswith(".enc"):
        print(f"Skipping non-encrypted file: {file_path}")
        return

    decrypted_file_path = file_path[:-4] # Remove .enc extension

    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        
        decrypted_data = f.decrypt(encrypted_data)
        
        with open(decrypted_file_path, "wb") as file:
            file.write(decrypted_data)
        
        os.remove(file_path) # Remove original encrypted file after decryption
        print(f"Decrypted: {file_path} -> {decrypted_file_path}")
    except Exception as e:
        print(f"Failed to decrypt {file_path}: {e}")

def decrypt_folder_files(folder_path, key):
    """Decrypts all .enc files in the specified folder."""
    if not os.path.isdir(folder_path):
        print(f"Error: Folder not found at {folder_path}")
        return

    for root, _, files in os.walk(folder_path):
        for filename in files:
            if filename.endswith(".enc"):
                file_path = os.path.join(root, filename)
                decrypt_file(file_path, key)

if __name__ == "__main__":
    folder_to_decrypt = input("Enter the full path of the folder containing .enc files to decrypt: ")
    
    encryption_key = load_key()

    if encryption_key:
        decrypt_folder_files(folder_to_decrypt, encryption_key)
        print("\nDecryption process finished.")
    else:
        print("Could not proceed with decryption without the encryption key.")
