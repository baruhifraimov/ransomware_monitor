"""
Utility functions for hashing and other helpers.
"""
import hashlib


def compute_file_hash(path):
    """
    Compute SHA-256 hash of a file's contents.
    """
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()
