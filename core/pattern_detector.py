"""
Advanced pattern detection for encrypted files.

Performance:
    - Memory Usage: O(m) - Depends on file size (m) for pattern analysis
    - Runtime Complexity: O(m) - Linear scan through file contents
    - I/O Complexity: Low - Only reads files during active events
"""
import re
import os
import base64
import binascii
import math
from collections import Counter

# Regular expressions for various hash formats
HASH_PATTERNS = {
    'MD5': r'\b[a-fA-F0-9]{32}\b',
    'SHA-1': r'\b[a-fA-F0-9]{40}\b',
    'SHA-256': r'\b[a-fA-F0-9]{64}\b',
    'SHA-512': r'\b[a-fA-F0-9]{128}\b',
    'SHA-3': r'\b[a-fA-F0-9]{64,128}\b',  # SHA-3 has variable output lengths
    'bcrypt': r'\$2[ayb]\$[0-9]{2}\$[a-zA-Z0-9./]{53}',
    'scrypt': r'\$scrypt\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+',
    'Argon2': r'\$argon2[id]\$v=\d+\$m=\d+,t=\d+,p=\d+\$[a-zA-Z0-9+/]+\$[a-zA-Z0-9+/]+'
}

# Regular expressions for encryption patterns
ENCRYPTION_PATTERNS = {
    'AES-header': r'Salted__[a-zA-Z0-9+/=]{8,}',
    'AES-base64': r'\b(?:[a-zA-Z0-9+/]{4})*(?:[a-zA-Z0-9+/]{2}==|[a-zA-Z0-9+/]{3}=)?\b',
    'RSA-header': r'-----BEGIN (RSA )?ENCRYPTED[^-]+?-----(.+?)-----END (RSA )?ENCRYPTED[^-]+?-----',
    'RSA-base64': r'\bMII[a-zA-Z0-9+/=]{10,}\b',
    'ECC-header': r'-----BEGIN EC PRIVATE KEY-----',
    'ChaCha20': r'(?:[A-Za-z0-9+/]{4}){16,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    # Extended encryption patterns used by hackers
    'Blowfish': r'(?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    'Twofish': r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    'RC4': r'(?:[a-zA-Z0-9+/]{4}){4,}(?:[a-zA-Z0-9+/]{2}==|[a-zA-Z0-9+/]{3}=)?',
    '3DES': r'(?:[a-zA-Z0-9+/]{4}){5,}(?:[a-zA-Z0-9+/]{2}==|[a-zA-Z0-9+/]{3}=)?',
    'Salsa20': r'(?:[A-Za-z0-9+/]{4}){16,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    'PGP': r'-----BEGIN PGP MESSAGE-----(.+?)-----END PGP MESSAGE-----',
    'GOST': r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    'Camellia': r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    'Serpent': r'(?:[A-Za-z0-9+/]{4}){12,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    'CAST': r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    'TEA': r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    'XTEA': r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    'Rabbit': r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
    'XOR': r'(?:[\x00-\xff]{4,})'  # Basic pattern for XOR-encrypted data
}

# Byte patterns that may indicate specific encryption types
ENCRYPTION_BYTE_SIGNATURES = {
    'AES': [b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f', b'AES'],
    '3DES': [b'\xDE\xAD\xBE\xEF', b'3DES'],
    'Blowfish': [b'Blowfish', b'\xA0\xB1\xC2\xD3\xE4\xF5'],
    'RC4': [b'RC4', b'\xAA\xBB\xCC\xDD'],
    'ChaCha20': [b'expand 32-byte k'],
    'Salsa20': [b'expand 32-byte k'],
    'RSA': [b'\x30\x82', b'RSA', b'BEGIN ENCRYPTED'],
    'PGP': [b'-----BEGIN PGP', b'PGP MESSAGE'],
    'GOST': [b'GOST', b'\x50\x47\x4F\x53\x54'],
    'XOR': [b'\xFF\xFF\xFF\xFF', b'\x00\x00\x00\x00', b'\x55\x55\x55\x55', b'\xAA\xAA\xAA\xAA']
}

def is_likely_base64(text):
    """Check if a string appears to be base64 encoded."""
    if not isinstance(text, str):
        return False
    
    # Basic checks for Base64 format
    if len(text) % 4 != 0:
        return False

    base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if not all(c in base64_chars for c in text):
        return False
    
    # Try to decode it
    try:
        decoded = base64.b64decode(text)
        # Base64-encoded text that decodes to binary is likely encryption
        # We count non-printable characters
        non_printable = sum(1 for byte in decoded if byte < 32 or byte > 126)
        return non_printable / len(decoded) > 0.3  # If >30% are non-printable
    except:
        return False

def detect_binary_content(data, threshold=0.3):
    """Check if content appears to be binary/encrypted based on byte distribution."""
    if not data:
        return False
    
    # Count non-printable ASCII characters
    non_printable = sum(1 for byte in data if byte < 32 or byte > 126)
    ratio = non_printable / len(data)
    
    return ratio > threshold

def detect_encryption_algorithm_from_bytes(data):
    """
    Try to detect encryption algorithm based on byte patterns.
    Returns a dictionary of possible encryption algorithms found.
    """
    results = {}
    
    if not data or len(data) < 16:
        return results
        
    # Check for algorithm signatures
    for algo, signatures in ENCRYPTION_BYTE_SIGNATURES.items():
        for sig in signatures:
            if sig in data:
                results[f'encryption_signature_{algo}'] = True
                break
    
    # Check for XOR-encrypted data by looking at byte distribution
    if len(data) >= 256:  # Need reasonable amount of data
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy of the byte distribution
        total_bytes = len(data)
        entropy = 0
        for count in byte_counts:
            if count > 0:
                p = count / total_bytes
                entropy -= p * math.log2(p)
        
        # High entropy (close to 8 bits) often indicates encryption or compression
        if entropy > 7.8:  # Very high entropy
            results['encryption_high_entropy'] = entropy
            
        # Check for repeating XOR patterns (common in simple XOR encryption)
        repeating_patterns = False
        for length in [1, 2, 4, 8]:  # Common XOR key lengths
            if len(data) >= length * 3:  # Need enough data to check patterns
                chunks = [data[i:i+length] for i in range(0, len(data) - length, length)]
                common_chunks = Counter(chunks).most_common(3)
                if common_chunks and common_chunks[0][1] > len(chunks) / 3:
                    repeating_patterns = True
                    break
        
        if repeating_patterns:
            results['encryption_repeating_xor'] = True
    
    # Check for block cipher characteristics (even distribution, block boundaries)
    if len(data) >= 64:  # Need enough data to check block patterns
        # Most block ciphers use 128-bit (16 byte) or 64-bit (8 byte) blocks
        # Check if data length is a multiple of common block sizes
        if len(data) % 8 == 0:
            blocks_8byte = [data[i:i+8] for i in range(0, len(data), 8)]
            unique_blocks = len(set(blocks_8byte))
            if unique_blocks / len(blocks_8byte) > 0.9:  # Almost all blocks different
                results['encryption_block_cipher_8byte'] = True
                
        if len(data) % 16 == 0:
            blocks_16byte = [data[i:i+16] for i in range(0, len(data), 16)]
            unique_blocks = len(set(blocks_16byte))
            if unique_blocks / len(blocks_16byte) > 0.9:  # Almost all blocks different
                results['encryption_block_cipher_16byte'] = True
    
    return results

def detect_hash_and_encryption_patterns(file_path):
    """
    Analyze file content for known hash and encryption patterns.
    Returns a dict with detected patterns and their counts.
    """
    detected_patterns = {}
    
    try:
        # First analyze for binary content
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Check if the file is binary/encrypted
        if detect_binary_content(data):
            detected_patterns['binary_content'] = True
            # Further analysis on binary content to identify encryption algorithm
            algo_detection = detect_encryption_algorithm_from_bytes(data)
            detected_patterns.update(algo_detection)
            return detected_patterns
        
        # For text analysis, convert to string if possible
        try:
            text_content = data.decode('utf-8')
        except UnicodeDecodeError:
            # If we can't decode as UTF-8, it's likely binary/encrypted
            detected_patterns['binary_content'] = True
            algo_detection = detect_encryption_algorithm_from_bytes(data)
            detected_patterns.update(algo_detection)
            return detected_patterns
        
        # Check for hash patterns
        for hash_type, pattern in HASH_PATTERNS.items():
            matches = re.findall(pattern, text_content)
            if matches:
                detected_patterns[f'hash_{hash_type}'] = len(matches)
        
        # Check for encryption patterns
        for enc_type, pattern in ENCRYPTION_PATTERNS.items():
            try:
                matches = re.findall(pattern, text_content, re.DOTALL)
                if matches:
                    detected_patterns[f'encryption_{enc_type}'] = len(matches)
            except re.error:
                # Skip if regex fails (some patterns might be too complex)
                continue
        
        # Additional check for large Base64 blocks
        # Split the text into lines and check each line
        lines = text_content.splitlines()
        base64_lines = 0
        for line in lines:
            line = line.strip()
            if len(line) > 40 and is_likely_base64(line):  # Long lines that look like base64
                base64_lines += 1
                
        if base64_lines > 0:
            detected_patterns['encryption_Base64_blocks'] = base64_lines
            
        # If we found base64 content, try decoding some of it to look for encryption signatures
        if 'encryption_Base64_blocks' in detected_patterns:
            for line in lines:
                if len(line) > 40 and is_likely_base64(line):
                    try:
                        decoded = base64.b64decode(line)
                        algo_detection = detect_encryption_algorithm_from_bytes(decoded)
                        detected_patterns.update(algo_detection)
                    except:
                        pass
            
    except Exception as e:
        # If we can't analyze the file, don't report any patterns
        pass
    
    return detected_patterns

def calculate_change_ratio(original_content, new_content):
    """
    Calculate the ratio of changes between two content versions.
    Returns a float between 0.0 (no change) and 1.0 (completely different).
    """
    if not original_content and not new_content:
        return 0.0
    elif not original_content or not new_content:
        return 1.0
    
    # If contents are binary, compare byte by byte
    if isinstance(original_content, bytes) and isinstance(new_content, bytes):
        total_bytes = max(len(original_content), len(new_content))
        if total_bytes == 0:
            return 0.0
            
        # Count changed bytes
        min_length = min(len(original_content), len(new_content))
        changed_bytes = sum(1 for i in range(min_length) if original_content[i] != new_content[i])
        
        # Add bytes that are in one content but not the other
        changed_bytes += abs(len(original_content) - len(new_content))
        
        return changed_bytes / total_bytes
    
    # If contents are strings, compare character by character
    else:
        # Ensure we're working with strings
        if not isinstance(original_content, str):
            original_content = str(original_content)
        if not isinstance(new_content, str):
            new_content = str(new_content)
            
        total_chars = max(len(original_content), len(new_content))
        if total_chars == 0:
            return 0.0
            
        # Count changed characters
        min_length = min(len(original_content), len(new_content))
        changed_chars = sum(1 for i in range(min_length) if original_content[i] != new_content[i])
        
        # Add characters that are in one content but not the other
        changed_chars += abs(len(original_content) - len(new_content))
        
        return changed_chars / total_chars