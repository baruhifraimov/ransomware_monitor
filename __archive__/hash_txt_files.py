"""
TXT File Hashing Utility

Purpose:
This script calculates and displays the SHA256 hash for the content of all .txt
files within a specified folder. Hashing is useful for verifying file integrity
or for creating a baseline of file states.

How to Run:
1. Ensure you have Python installed.
2. Navigate to the script's directory in your terminal.
3. Run the script using the command: python hash_txt_files.py
4. When prompted, enter the full path to the folder containing the .txt files
   you wish to hash.
   Example: /Users/yourusername/Documents/MyTextFiles

Output:
The script will print the file path and its corresponding SHA256 hash for each
.txt file found in the specified directory and its subdirectories.

Dependencies:
- None (uses built-in Python libraries 'os' and 'hashlib')
"""

import os
import hashlib

def calculate_sha256(file_path):
    """Calculates SHA256 hash of a file's content."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

def hash_txt_files_in_folder(folder_path):
    """Calculates and prints SHA256 hashes for all .txt files in a folder."""
    if not os.path.isdir(folder_path):
        print(f"Error: Folder not found at {folder_path}")
        return

    print(f"Calculating SHA256 hashes for .txt files in: {folder_path}\n")
    found_txt_files = False
    for root, _, files in os.walk(folder_path):
        for filename in files:
            if filename.endswith(".txt"):
                found_txt_files = True
                file_path = os.path.join(root, filename)
                file_hash = calculate_sha256(file_path)
                if file_hash:
                    print(f"File: {file_path} | SHA256 Hash: {file_hash}")
    
    if not found_txt_files:
        print(f"No .txt files found in {folder_path}")

if __name__ == "__main__":
    target_folder = input("Enter the full path of the folder to hash .txt files from: ")
    hash_txt_files_in_folder(target_folder)
    print("\nHashing process finished.")
