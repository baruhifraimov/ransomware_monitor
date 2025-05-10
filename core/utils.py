"""
Utility functions for file operations.

Performance:
    - Memory Usage: O(m) - Memory usage scales with file size for hashing
    - Runtime Complexity: O(m) - Linear processing time based on file size
    - I/O Complexity: Low - Only reads files when explicitly called
"""
import hashlib


def compute_file_hash(path):
    """
    Calculate the SHA256 hash of a file.
    Returns hex digest or None if file can't be read.
    """
    try:
        hasher = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        return None
