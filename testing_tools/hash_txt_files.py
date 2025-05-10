"""
TXT File "Ransomware" Simulator

Purpose:
This script not only calculates hashes but also modifies .txt files to simulate 
different ransomware attacks. It applies various transformation techniques to the 
file content based on the chosen ransomware pattern.

How to Run:
1. Ensure you have Python installed.
2. Navigate to the main project directory in your terminal.
3. Run the script using the command: python testing_tools/hash_txt_files.py
4. Select the ransomware simulation you want to use from the menu.
5. When prompted, enter the path to the folder (relative to main dir or absolute)
   containing the .txt files you wish to transform.

Output:
The script will modify each .txt file according to the chosen ransomware pattern,
and display the file path and its corresponding hash.

Ransomware Simulation Options:
- WannaCry (May 2017) - Base64 encoding with custom format
- NotPetya (June 2017) - XOR encryption with custom suffix
- Colonial Pipeline (May 7, 2021) - Reverse text with MD5 prefix
- JBS USA (May 30, 2021) - Double Base64 encoding
- Costa Rica Government (April 17, 2022) - Caesar cipher (ROT13)
- Swissport (Feb 3, 2022) - Binary representation 
- Caesars and MGM Casinos (September 2023) - Hex encoding with custom prefix
- Change Healthcare (Feb 21, 2024) - Character substitution
- Ascension (May 8, 2024) - ROT47 encryption
- CDK Global (June 8, 2024) - Morse code transformation

Dependencies:
- hashlib (built-in)
- os (built-in)
- base64 (built-in)
"""

import os
import hashlib
import sys
import base64
import random
import string
import binascii
from typing import Callable, Dict, Optional, Tuple

# Get the main directory (two levels up from this file)
MAIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Create backup folder for original files
BACKUP_DIR = os.path.join(MAIN_DIR, "backup_txt_files")
if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)

# Define ransomware simulation functions
class RansomwareSimulators:
    @staticmethod
    def backup_file(file_path: str) -> bool:
        """Creates a backup of the original file before modification."""
        try:
            filename = os.path.basename(file_path)
            backup_path = os.path.join(BACKUP_DIR, filename)
            
            # If no backup exists yet, create one
            if not os.path.exists(backup_path):
                with open(file_path, "rb") as src:
                    with open(backup_path, "wb") as dst:
                        dst.write(src.read())
            return True
        except Exception as e:
            print(f"Error backing up file {file_path}: {e}")
            return False

    @staticmethod
    def wannacry_transform(data: bytes) -> Tuple[bytes, str]:
        """Base64 encoding with WannaCry-like prefix"""
        encoded_data = base64.b64encode(data)
        sha256_hash = hashlib.sha256(data).hexdigest()
        header = f"WNCRY:{sha256_hash[:16]}...\n".encode()
        
        transformed = header + encoded_data
        hash_value = f"WNCRY:{sha256_hash[:16]}...{sha256_hash[-16:]}"
        return transformed, hash_value
    
    @staticmethod
    def notpetya_transform(data: bytes) -> Tuple[bytes, str]:
        """XOR encryption with NotPetya-like suffix"""
        key = b'petya'  # Simple XOR key
        encrypted = bytearray(len(data))
        for i in range(len(data)):
            encrypted[i] = data[i] ^ key[i % len(key)]
        
        sha1_hash = hashlib.sha1(data).hexdigest().upper()
        footer = f"\n\n.encrypted_{sha1_hash[:8]}".encode()
        
        transformed = bytes(encrypted) + footer
        hash_value = f"{sha1_hash}.encrypted"
        return transformed, hash_value
    
    @staticmethod
    def colonial_pipeline_transform(data: bytes) -> Tuple[bytes, str]:
        """Reverse text with MD5 prefix"""
        text = data.decode('utf-8', errors='replace')
        reversed_text = text[::-1]  # Reverse the text
        md5_hash = hashlib.md5(data).hexdigest()
        
        header = f"DARKSIDE-{md5_hash[:10]}\n".encode()
        transformed = header + reversed_text.encode()
        hash_value = md5_hash
        return transformed, hash_value
    
    @staticmethod
    def jbs_usa_transform(data: bytes) -> Tuple[bytes, str]:
        """Double Base64 encoding"""
        encoded_once = base64.b64encode(data)
        encoded_twice = base64.b64encode(encoded_once)
        
        blake2b_hash = hashlib.blake2b(data).hexdigest()
        header = f"REvil-{blake2b_hash[:16]}\n".encode()
        
        transformed = header + encoded_twice
        hash_value = blake2b_hash
        return transformed, hash_value
    
    @staticmethod
    def costa_rica_transform(data: bytes) -> Tuple[bytes, str]:
        """Caesar cipher (ROT13)"""
        text = data.decode('utf-8', errors='replace')
        rot13_chars = []  # Use a list for efficient char collection
        for char in text:
            if 'a' <= char <= 'z':
                # Shift lowercase letter by 13 positions
                rot13_chars.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                # Shift uppercase letter by 13 positions
                rot13_chars.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                # Non-alphabetic characters are unchanged
                rot13_chars.append(char)
                
        sha384_hash = hashlib.sha384(data).hexdigest() # Hashes original data
        header = f"CONTI-LOCK-{sha384_hash[:10]}\n".encode()
        
        transformed_text = "".join(rot13_chars)
        transformed = header + transformed_text.encode('utf-8')
        hash_value = sha384_hash # Returns the hash of the original data
        return transformed, hash_value
    
    @staticmethod
    def swissport_transform(data: bytes) -> Tuple[bytes, str]:
        """Binary representation"""
        text = data.decode('utf-8', errors='replace')
        binary = ' '.join(format(ord(c), '08b') for c in text)
        
        sha512_hash = hashlib.sha512(data).digest()
        b64_hash = base64.b64encode(sha512_hash).decode('utf-8')
        header = f"SWISSPORT-LOCKED\n".encode()
        
        transformed = header + binary.encode()
        hash_value = b64_hash
        return transformed, hash_value
    
    @staticmethod
    def caesars_mgm_transform(data: bytes) -> Tuple[bytes, str]:
        """Hex encoding with custom prefix"""
        hex_data = binascii.hexlify(data)
        
        if hasattr(hashlib, 'shake_128'):
            shake_hash = hashlib.shake_128(data).hexdigest(32)
        else:
            shake_hash = hashlib.sha256(data).hexdigest()
            
        header = f"ALPHV-BLACKCAT-{shake_hash[:10]}\n".encode()
        
        transformed = header + hex_data
        hash_value = f"ALPHV-{shake_hash}"
        return transformed, hash_value
    
    @staticmethod
    def change_healthcare_transform(data: bytes) -> Tuple[bytes, str]:
        """Character substitution"""
        text = data.decode('utf-8', errors='replace')
        substitution = ""
        for char in text:
            if char.isalpha():
                # Replace with a fixed character based on position in alphabet
                if char.islower():
                    substitution += chr(219 - ord(char))
                else:
                    substitution += chr(155 - ord(char))
            else:
                substitution += char
                
        blake2s_hash = hashlib.blake2s(data).hexdigest()
        header = f"ALPHV-2024-{blake2s_hash[:10]}\n".encode()
        
        transformed = header + substitution.encode()
        hash_value = blake2s_hash
        return transformed, hash_value
    
    @staticmethod
    def ascension_transform(data: bytes) -> Tuple[bytes, str]:
        """ROT47 encryption (shifts visible ASCII by 47 positions)"""
        text = data.decode('utf-8', errors='replace')
        rot47 = ""
        for char in text:
            # ROT47 operates on visible ASCII characters (33-126)
            if 33 <= ord(char) <= 126:
                rot47 += chr(33 + (ord(char) + 14) % 94)
            else:
                rot47 += char
                
        if hasattr(hashlib, 'sha3_256'):
            sha3_hash = hashlib.sha3_256(data).hexdigest()
        else:
            sha3_hash = hashlib.sha256(data).hexdigest()
            
        header = f"LOCKBIT-ASC-{sha3_hash[:10]}\n".encode()
        
        transformed = header + rot47.encode()
        hash_value = sha3_hash
        return transformed, hash_value
    
    @staticmethod
    def cdk_global_transform(data: bytes) -> Tuple[bytes, str]:
        """Morse code transformation"""
        MORSE_CODE_DICT = { 'A':'.-', 'B':'-...', 'C':'-.-.', 'D':'-..', 'E':'.', 'F':'..-.', 
                    'G':'--.', 'H':'....', 'I':'..', 'J':'.---', 'K':'-.-', 'L':'.-..', 
                    'M':'--', 'N':'-.', 'O':'---', 'P':'.--.', 'Q':'--.-', 'R':'.-.', 
                    'S':'...', 'T':'-', 'U':'..-', 'V':'...-', 'W':'.--', 'X':'-..-', 
                    'Y':'-.--', 'Z':'--..', '1':'.----', '2':'..---', '3':'...--', 
                    '4':'....-', '5':'.....', '6':'-....', '7':'--...', '8':'---..', 
                    '9':'----.', '0':'-----', ', ':'--..--', '.':'.-.-.-', '?':'..--..', 
                    '/':'-..-.', '-':'-....-', '(':'-.--.', ')':'-.--.-', ' ':'/' }
        
        text = data.decode('utf-8', errors='replace')
        morse = ""
        for char in text:
            if char.upper() in MORSE_CODE_DICT:
                morse += MORSE_CODE_DICT[char.upper()] + ' '
            else:
                morse += char
                
        if hasattr(hashlib, 'sha3_512'):
            sha3_hash = hashlib.sha3_512(data).hexdigest()
        else:
            sha512_hash = hashlib.sha512(data).hexdigest()
            sha3_hash = sha512_hash
            
        header = f"LOCKBIT-CDK-{sha3_hash[:10]}\n".encode()
        
        transformed = header + morse.encode()
        hash_value = f"LockBit-{sha3_hash[:20]}..{sha3_hash[-20:]}"
        return transformed, hash_value

def transform_and_hash(file_path: str, transform_function: Callable[[bytes], Tuple[bytes, str]]) -> Optional[str]:
    """Transforms a file's content using the provided transform function and saves it."""
    try:
        # First backup the file
        if not RansomwareSimulators.backup_file(file_path):
            print(f"Error: Could not backup {file_path}, skipping transformation")
            return None
            
        # Read original content
        with open(file_path, "rb") as f:
            data = f.read()
            
        # Apply transformation
        transformed_content, hash_value = transform_function(data)
        
        # Write transformed content back to the file
        with open(file_path, "wb") as f:
            f.write(transformed_content)
            
        return hash_value
    except Exception as e:
        print(f"Error transforming file {file_path}: {e}")
        return None

def transform_txt_files_in_folder(folder_path: str, transform_function: Callable[[bytes], Tuple[bytes, str]], ransomware_name: str):
    """Transforms all .txt files in a folder using the selected ransomware simulation."""
    # Convert to absolute path if it's a relative path
    if not os.path.isabs(folder_path):
        folder_path = os.path.join(MAIN_DIR, folder_path)
        
    if not os.path.isdir(folder_path):
        print(f"Error: Folder not found at {folder_path}")
        return

    print(f"Applying {ransomware_name} ransomware simulation to .txt files in: {folder_path}\n")
    found_txt_files = False
    
    # Just process files in the specified folder, not in subfolders
    for filename in os.listdir(folder_path):
        if filename.endswith(".txt"):
            found_txt_files = True
            file_path = os.path.join(folder_path, filename)
            hash_value = transform_and_hash(file_path, transform_function)
            if hash_value:
                print(f"Transformed: {filename} | {ransomware_name} Hash: {hash_value}")
    
    if not found_txt_files:
        print(f"No .txt files found in {folder_path}")
    else:
        print(f"\nBackup of original files created in: {BACKUP_DIR}")

def restore_files():
    """Restores original files from backups."""
    if not os.path.exists(BACKUP_DIR):
        print("No backups found to restore.")
        return
        
    print("Restoring files from backups...")
    restored_count = 0
    
    for filename in os.listdir(BACKUP_DIR):
        if filename.endswith(".txt"):
            backup_path = os.path.join(BACKUP_DIR, filename)
            
            # Find all directories that might contain this file in the main directory
            for root, dirs, files in os.walk(MAIN_DIR):
                # Skip the backup directory itself
                if root == BACKUP_DIR:
                    continue
                    
                target_path = os.path.join(root, filename)
                if os.path.exists(target_path):
                    try:
                        # Restore the backup
                        with open(backup_path, "rb") as src:
                            with open(target_path, "wb") as dst:
                                dst.write(src.read())
                        print(f"Restored: {target_path}")
                        restored_count += 1
                    except Exception as e:
                        print(f"Error restoring {target_path}: {e}")
    
    if restored_count > 0:
        print(f"\nSuccessfully restored {restored_count} files.")
    else:
        print("No matching files found to restore.")

def display_menu():
    """Display menu of ransomware simulation options."""
    print("\n===== TXT File Ransomware Simulator Menu =====")
    print("Select ransomware simulation:")
    print("1. WannaCry (May 2017) - Base64 encoding with custom format")
    print("2. NotPetya (June 2017) - XOR encryption with custom suffix")
    print("3. Colonial Pipeline (May 7, 2021) - Reverse text with MD5 prefix")
    print("4. JBS USA (May 30, 2021) - Double Base64 encoding")
    print("5. Costa Rica Government (April 17, 2022) - Caesar cipher (ROT13)")
    print("6. Swissport (Feb 3, 2022) - Binary representation")
    print("7. Caesars and MGM Casinos (September 2023) - Hex encoding with custom prefix")
    print("8. Change Healthcare (Feb 21, 2024) - Character substitution")
    print("9. Ascension (May 8, 2024) - ROT47 encryption")
    print("10. CDK Global (June 8, 2024) - Morse code transformation")
    print("R. Restore files from backup")
    print("0. Exit")
    
    choice = input("\nEnter option number (0-10) or 'R' to restore: ")
    return choice

if __name__ == "__main__":
    # Make sure the working directory is the main directory
    os.chdir(MAIN_DIR)
    
    # Define the mapping between menu options and transform functions
    transform_options = {
        "1": (RansomwareSimulators.wannacry_transform, "WannaCry"),
        "2": (RansomwareSimulators.notpetya_transform, "NotPetya"),
        "3": (RansomwareSimulators.colonial_pipeline_transform, "Colonial Pipeline"),
        "4": (RansomwareSimulators.jbs_usa_transform, "JBS USA"),
        "5": (RansomwareSimulators.costa_rica_transform, "Costa Rica"),
        "6": (RansomwareSimulators.swissport_transform, "Swissport"),
        "7": (RansomwareSimulators.caesars_mgm_transform, "Caesars/MGM"),
        "8": (RansomwareSimulators.change_healthcare_transform, "Change Healthcare"),
        "9": (RansomwareSimulators.ascension_transform, "Ascension"),
        "10": (RansomwareSimulators.cdk_global_transform, "CDK Global"),
    }
    
    while True:
        choice = display_menu()
        
        if choice == "0":
            print("Exiting program.")
            sys.exit(0)
            
        if choice.upper() == "R":
            restore_files()
            continue
        
        if choice not in transform_options:
            print("Invalid option. Please try again.")
            continue
        
        transform_function, ransomware_name = transform_options[choice]
        
        target_folder = input("\nEnter the folder path to transform .txt files in (relative to main dir or absolute): ")
        
        # Confirm before transforming
        confirm = input(f"Warning: This will modify .txt files in '{target_folder}' to simulate {ransomware_name} ransomware. Continue? (y/n): ")
        if confirm.lower() != 'y':
            print("Operation cancelled.")
            continue
            
        transform_txt_files_in_folder(target_folder, transform_function, ransomware_name)
        print("\nTransformation process finished.")
        
        continue_choice = input("\nPress Enter to return to menu or 'q' to quit: ")
        if continue_choice.lower() == 'q':
            break
