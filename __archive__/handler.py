"""
File system event handler that bridges Watchdog events to detection logic.
"""
import os
import time
import fnmatch
import re
from watchdog.events import FileSystemEventHandler
from config import TARGET_FILE_EXTENSIONS, ENCRYPTED_EXTENSIONS, PATH_WHITELIST
from detector import RansomwareDetector
from logger import logger

class RansomwareEventHandler(FileSystemEventHandler):
    """Handles file system events and passes them to the RansomwareDetector."""
    def __init__(self):
        super().__init__()
        self.detector = RansomwareDetector()
        # Regex patterns for encrypted files
        self.txt_encrypted_patterns = [
            r'\.txt\.[^.]+$',  # Matches .txt.<anything> like .txt.enc, .txt.locked, etc.
            r'\.txt[^.]+$'      # Matches .txt<anything> like .txtenc, .txtlocked, etc.
        ]
        logger.info("RansomwareEventHandler initialized.")

    def _is_whitelisted(self, path):
        """Check if the path is whitelisted."""
        for item in PATH_WHITELIST:
            if item.endswith('/') and path.startswith(os.path.normpath(item)):  # Whitelisted directory
                return True
            elif not item.endswith('/') and os.path.normpath(path).endswith(item):  # Whitelisted file or pattern
                if "*" in item and fnmatch.fnmatch(os.path.basename(path), item):
                    return True
                elif os.path.basename(path) == item:
                    return True
        return False

    def _is_target_or_encrypted_ext(self, path):
        """Check if the file extension is in TARGET_FILE_EXTENSIONS or ENCRYPTED_EXTENSIONS."""
        path_lower = path.lower()
        
        # Check against explicit extensions first
        is_target = any(path_lower.endswith(ext) for ext in TARGET_FILE_EXTENSIONS)
        is_encrypted_explicit = any(path_lower.endswith(ext) for ext in ENCRYPTED_EXTENSIONS)
        
        # If not matching explicit extensions, check against regex patterns for encrypted text files
        is_txt_encrypted = False
        if not is_encrypted_explicit and '.txt' in path_lower:
            is_txt_encrypted = any(re.search(pattern, path_lower) for pattern in self.txt_encrypted_patterns)
            
        return is_target or is_encrypted_explicit or is_txt_encrypted

    def _is_encrypted_ext(self, path):
        """Check if the file extension indicates encryption."""
        path_lower = path.lower()
        
        # Check against explicit encrypted extensions
        is_encrypted_explicit = any(path_lower.endswith(ext) for ext in ENCRYPTED_EXTENSIONS)
        
        # Check against regex patterns for encrypted text files
        is_txt_encrypted = False
        if not is_encrypted_explicit and '.txt' in path_lower:
            is_txt_encrypted = any(re.search(pattern, path_lower) for pattern in self.txt_encrypted_patterns)
            
        return is_encrypted_explicit or is_txt_encrypted

    def _is_target_ext(self, path):
        """Check if the file extension is in TARGET_FILE_EXTENSIONS."""
        path_lower = path.lower()
        return any(path_lower.endswith(ext) for ext in TARGET_FILE_EXTENSIONS)

    def on_created(self, event):
        super().on_created(event)
        if not event.is_directory:
            path = event.src_path
            if self._is_whitelisted(path):
                logger.debug(f"Ignoring whitelisted file created: {path}")
                return

            logger.debug(f"File created: {path}")
            if self._is_target_or_encrypted_ext(path):
                self.detector.process_event(path, event_type="created")
            else:
                logger.debug(f"Ignoring creation of non-target/non-encrypted file type: {path}")

    def on_modified(self, event):
        super().on_modified(event)
        if not event.is_directory:
            path = event.src_path
            if self._is_whitelisted(path):
                logger.debug(f"Ignoring whitelisted file modified: {path}")
                return

            logger.debug(f"File modified: {path}")
            if self._is_target_or_encrypted_ext(path):
                self.detector.process_event(path, event_type="modified")
            else:
                logger.debug(f"Ignoring modification of non-target/non-encrypted file type: {path}")

    def on_deleted(self, event):
        super().on_deleted(event)
        if not event.is_directory:
            path = event.src_path
            if self._is_whitelisted(path):
                logger.debug(f"Ignoring whitelisted file deleted: {path}")
                return

            logger.debug(f"File deleted: {path}")
            
            is_target = self._is_target_ext(path)
            is_encrypted = self._is_encrypted_ext(path)

            if is_target:
                self.detector.process_event(path, event_type="deleted_target")
            elif is_encrypted:
                self.detector.process_event(path, event_type="deleted_encrypted")
            else:
                self.detector.process_event(path, event_type="deleted_unknown")
                logger.debug(f"Deletion of non-target/non-encrypted file type (or unknown to handler): {path}")

    def on_moved(self, event):
        super().on_moved(event)
        if not event.is_directory:
            src_path = event.src_path
            dest_path = event.dest_path

            if self._is_whitelisted(src_path) and self._is_whitelisted(dest_path):
                logger.debug(f"Ignoring move of whitelisted files: {src_path} to {dest_path}")
                return
            if self._is_whitelisted(dest_path) and not self._is_whitelisted(src_path):
                logger.info(f"File {src_path} moved to a whitelisted path {dest_path}. Treating original as deleted if it was monitored.")
                if self._is_target_ext(src_path):
                    self.detector.process_event(src_path, event_type="deleted_target_moved_to_whitelist", original_path=src_path)
                return

            logger.debug(f"File moved/renamed: from {src_path} to {dest_path}")

            src_is_target = self._is_target_ext(src_path)
            dest_is_target = self._is_target_ext(dest_path)
            dest_is_encrypted = self._is_encrypted_ext(dest_path)

            if src_is_target and dest_is_encrypted:
                logger.info(f"TARGET file {src_path} RENAMED TO ENCRYPTED extension {dest_path}. Highly suspicious.")
                self.detector.process_event(dest_path, event_type="renamed_target_to_encrypted", original_path=src_path)
            elif not src_is_target and dest_is_encrypted:
                logger.info(f"File {src_path} (non-target/unknown) renamed to ENCRYPTED extension {dest_path}. Suspicious.")
                self.detector.process_event(dest_path, event_type="renamed_to_encrypted", original_path=src_path)
            elif src_is_target and not dest_is_target and not dest_is_encrypted:
                logger.info(f"Target file {src_path} renamed to non-target/non-encrypted type {dest_path}. Treating original as deleted.")
                self.detector.process_event(src_path, event_type="deleted_target_renamed_other", original_path=src_path)
            elif dest_is_target:
                logger.info(f"File {src_path} renamed to TARGET extension {dest_path}. Processing as modified/created.")
                self.detector.process_event(dest_path, event_type="renamed_to_target", original_path=src_path)
            else:
                if self._is_encrypted_ext(src_path) and dest_is_encrypted:
                    logger.info(f"Encrypted file {src_path} renamed to another encrypted name {dest_path}.")
                    self.detector.process_event(dest_path, event_type="renamed_encrypted_to_encrypted", original_path=src_path)
                else:
                    logger.debug(f"Ignoring move/rename of non-critical types: {src_path} to {dest_path}")
