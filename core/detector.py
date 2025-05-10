"""
Detection logic: entropy, hash comparison, and burst detection.

Performance:
    - Memory Usage: O(n × m) - Stores file baselines including full file content
      where n = number of monitored files and m = average file size
    - Runtime Complexity: O(n) - Linear processing for entropy calculations
      and pattern detection, with constant-time event history pruning
    - I/O Complexity: Low - Only reads files when events occur, not periodically
"""
import math
import time
import os
import numpy as np
from collections import deque, Counter
from config import (
    HIGH_ENTROPY_THRESHOLD, BURST_THRESHOLD_SECONDS, BURST_THRESHOLD_COUNT,
    TARGET_FILE_EXTENSIONS, ENCRYPTED_EXTENSIONS, MIN_ENTROPY_FILE_SIZE_BYTES,
    MAX_FILE_CHANGES_PER_SECOND, MAX_ENCRYPTION_LIKE_CHANGES_PER_SECOND,
    SLIDING_WINDOW_ENTROPY_THRESHOLD, DIFFERENTIAL_AREA_THRESHOLD,
    CHANGE_RATIO_THRESHOLD, RATE_CALCULATION_WINDOW
)
from utils import compute_file_hash
from pattern_detector import detect_hash_and_encryption_patterns, calculate_change_ratio
from logger import logger

class RansomwareDetector:
    def __init__(self):
        self.baselines = {}  # path -> {'hash': str, 'entropy': float, 'content': bytes, 'last_event': str, 'original_path': str or None, 'is_target': bool}
        self.suspicious_events_log = deque()  # For burst detection based on BURST_THRESHOLD_COUNT
        
        # For statistical rate-based detection (now using seconds instead of minutes)
        self.event_timestamps = deque()  # Stores timestamps of all processed relevant events
        self.encryption_like_event_timestamps = deque()  # Stores timestamps of high-risk events

        # Statistics for logging during burst alerts
        self.burst_stats = Counter()  # e.g., {'renamed_target_to_encrypted': 2, 'high_entropy_modification': 3}
        self.last_burst_alert_time = 0
        
        # Time of last rate alert to prevent alert flooding
        self.last_rate_alert_time = 0

    def calculate_entropy(self, path):
        """
        Calculate Shannon entropy of file contents in bits per byte.
        Returns None if file is empty, too small, or cannot be read.
        """
        try:
            if os.path.getsize(path) < MIN_ENTROPY_FILE_SIZE_BYTES:
                logger.debug(f"Skipping entropy for small file: {path}")
                return 0.0  # Return 0 for small files, as they are not considered for high entropy
        except OSError:  # File might have been deleted between event and this check
            logger.warning(f"Could not get size for entropy calculation (may be deleted): {path}")
            return None

        byte_counts = [0] * 256
        try:
            with open(path, 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            logger.error(f"Entropy calculation: File not found at {path}")
            return None
        except Exception as e:
            logger.error(f"Error reading file for entropy calculation {path}: {e}")
            return None
        
        total = len(data)
        if total == 0:
            return 0.0
        
        for b in data:
            byte_counts[b] += 1
        
        entropy = 0.0
        for count in byte_counts:
            if count == 0:
                continue
            p = count / total
            entropy -= p * math.log2(p)
        return entropy
    
    def calculate_sliding_window_entropy(self, path, window_size=4096):
        """
        Calculate entropy using a sliding window approach to detect localized encryption.
        Returns the highest window entropy value and number of high-entropy windows.
        """
        try:
            if os.path.getsize(path) < window_size:
                return self.calculate_entropy(path), 0  # For small files, just use regular entropy
        except OSError:
            return None, 0
        
        max_window_entropy = 0.0
        high_entropy_windows = 0
        
        try:
            with open(path, 'rb') as f:
                data = f.read()
                
            if len(data) <= window_size:
                entropy = self.calculate_entropy(path)
                return entropy, 1 if entropy >= SLIDING_WINDOW_ENTROPY_THRESHOLD else 0
            
            # Slide the window through the file
            for i in range(0, len(data) - window_size + 1, window_size // 2):  # Overlap windows by 50%
                window = data[i:i+window_size]
                byte_counts = [0] * 256
                
                for b in window:
                    byte_counts[b] += 1
                
                window_entropy = 0.0
                for count in byte_counts:
                    if count == 0:
                        continue
                    p = count / window_size
                    window_entropy -= p * math.log2(p)
                
                if window_entropy > max_window_entropy:
                    max_window_entropy = window_entropy
                
                if window_entropy >= SLIDING_WINDOW_ENTROPY_THRESHOLD:
                    high_entropy_windows += 1
            
            return max_window_entropy, high_entropy_windows
        except Exception as e:
            logger.error(f"Error calculating sliding window entropy for {path}: {e}")
            return None, 0
    
    def calculate_differential_area(self, path):
        """
        Compare file entropy profile with that of random data.
        Returns the differential area between the two profiles.
        Lower values indicate higher similarity to encrypted/random data.
        """
        try:
            with open(path, 'rb') as f:
                data = f.read()
                
            if len(data) < MIN_ENTROPY_FILE_SIZE_BYTES:
                return None  # File too small for meaningful analysis
                
            # Generate histogram of byte values
            hist = [0] * 256
            for b in data:
                hist[b] += 1
                
            # Normalize histogram
            total = len(data)
            hist = [count / total for count in hist]
            
            # Ideal random data has a uniform distribution across all byte values
            uniform_dist = [1/256] * 256
            
            # Calculate differential area (lower values = more similar to random data)
            diff_area = sum(abs(hist[i] - uniform_dist[i]) for i in range(256)) * 256
            
            return diff_area
        except Exception as e:
            logger.error(f"Error calculating differential area for {path}: {e}")
            return None

    def _update_activity_rates(self, is_encryption_like=False):
        """
        Updates general and encryption-like activity rates.
        Now calculates rates over a configurable time window (in seconds).
        """
        now = time.time()
        self.event_timestamps.append(now)
        if is_encryption_like:
            self.encryption_like_event_timestamps.append(now)

        # Prune old events (older than RATE_CALCULATION_WINDOW seconds for rate calculation)
        while self.event_timestamps and now - self.event_timestamps[0] > RATE_CALCULATION_WINDOW:
            self.event_timestamps.popleft()
        while self.encryption_like_event_timestamps and now - self.encryption_like_event_timestamps[0] > RATE_CALCULATION_WINDOW:
            self.encryption_like_event_timestamps.popleft()

        # Calculate rates per second
        general_events_count = len(self.event_timestamps)
        encryption_events_count = len(self.encryption_like_event_timestamps)
        
        general_events_rate = general_events_count / RATE_CALCULATION_WINDOW
        encryption_events_rate = encryption_events_count / RATE_CALCULATION_WINDOW

        # Limit rate alerts to once per alert window to prevent flooding
        if now - self.last_rate_alert_time > RATE_CALCULATION_WINDOW:
            if general_events_rate > MAX_FILE_CHANGES_PER_SECOND:
                self.last_rate_alert_time = now
                logger.warning(
                    f"STATISTICAL ALERT: High rate of general file changes detected: "
                    f"{general_events_rate:.1f} changes per second over last {RATE_CALCULATION_WINDOW} seconds "
                    f"(Threshold: {MAX_FILE_CHANGES_PER_SECOND} per second)."
                )
            if encryption_events_rate > MAX_ENCRYPTION_LIKE_CHANGES_PER_SECOND:
                self.last_rate_alert_time = now
                logger.critical(
                    f"STATISTICAL ALERT: High rate of ENCRYPTION-LIKE file changes detected: "
                    f"{encryption_events_rate:.1f} suspicious changes per second over last {RATE_CALCULATION_WINDOW} seconds "
                    f"(Threshold: {MAX_ENCRYPTION_LIKE_CHANGES_PER_SECOND} per second)."
                )

    def _update_suspicious_activity_log(self, file_path, event_type, details, is_high_risk=False):
        """Adds an event to the suspicious activity log and checks for burst activity."""
        now = time.time()
        log_entry = {
            'time': now,
            'path': file_path,
            'event': event_type,
            'details': details
        }
        self.suspicious_events_log.append(log_entry)
        self.burst_stats[event_type] += 1
        
        self._update_activity_rates(is_encryption_like=is_high_risk)

        # Prune old events from the suspicious_events_log and burst_stats
        while self.suspicious_events_log and now - self.suspicious_events_log[0]['time'] > BURST_THRESHOLD_SECONDS:
            old_event = self.suspicious_events_log.popleft()
            self.burst_stats[old_event['event']] -= 1
            if self.burst_stats[old_event['event']] <= 0:
                del self.burst_stats[old_event['event']]

        # Check for burst activity
        # Only trigger one major alert per BURST_THRESHOLD_SECONDS to avoid log flooding
        if len(self.suspicious_events_log) >= BURST_THRESHOLD_COUNT and \
           (now - self.last_burst_alert_time > BURST_THRESHOLD_SECONDS):
            self.last_burst_alert_time = now
            logger.critical(
                f"ALERT: BURST OF SUSPICIOUS ACTIVITY DETECTED - "
                f"{len(self.suspicious_events_log)} suspicious events within {BURST_THRESHOLD_SECONDS} seconds (Threshold: {BURST_THRESHOLD_COUNT})."
            )
            logger.critical(f"  Burst Statistics: {dict(self.burst_stats)}")
            # Log the specific events in the current burst for better diagnosis
            for event_log_entry in list(self.suspicious_events_log):  # Iterate over a copy
                logger.critical(f"    - Event: {event_log_entry['event']}, File: {event_log_entry['path']}, Details: {event_log_entry['details']}")

    def _get_file_content(self, path):
        """Read file content safely, returning None if the file can't be read."""
        try:
            with open(path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading file content for {path}: {e}")
            return None

    def process_event(self, path, event_type, original_path=None):
        logger.info(f"Processing event: {event_type} for {path} (Original: {original_path if original_path else 'N/A'})")
        current_hash = None
        current_entropy = None
        max_window_entropy = None
        high_entropy_windows = 0
        diff_area = None
        file_content = None
        suspicious_messages = []  # Renamed from suspicious_details for clarity
        pattern_detection_results = {}
        change_ratio = 0.0
        
        is_target_file = any(path.lower().endswith(ext) for ext in TARGET_FILE_EXTENSIONS)
        is_encrypted_file_type = any(path.lower().endswith(ext) for ext in ENCRYPTED_EXTENSIONS)
        
        is_high_risk_event = False  # Flag to mark events that strongly indicate ransomware

        if event_type not in ["deleted_target", "deleted_encrypted", "deleted_unknown", "deleted_target_renamed_other", "deleted_target_moved_to_whitelist"]:
            try:
                if os.path.exists(path):
                    # Only calculate hash and entropy if the file is not an already known encrypted type (unless it's a rename target)
                    # or if it's a target file type.
                    if not is_encrypted_file_type or event_type in ["renamed_target_to_encrypted", "renamed_to_encrypted"]:
                        current_hash = compute_file_hash(path)
                        file_content = self._get_file_content(path)
                        current_entropy = self.calculate_entropy(path)
                        
                        # Apply advanced entropy analysis for files large enough
                        if file_content and len(file_content) >= MIN_ENTROPY_FILE_SIZE_BYTES:
                            # Sliding window entropy analysis
                            max_window_entropy, high_entropy_windows = self.calculate_sliding_window_entropy(path)
                            
                            # Differential area analysis
                            diff_area = self.calculate_differential_area(path)
                            
                            # Pattern detection for hashes and encryption
                            pattern_detection_results = detect_hash_and_encryption_patterns(path)
                            
                            # Calculate change ratio if we have a baseline
                            baseline_key_lookup = original_path if original_path else path
                            prev_baseline = self.baselines.get(baseline_key_lookup)
                            if prev_baseline and 'content' in prev_baseline and prev_baseline['content'] is not None:
                                change_ratio = calculate_change_ratio(prev_baseline['content'], file_content)
                                logger.debug(f"Change ratio for {path}: {change_ratio:.2f} (threshold: {CHANGE_RATIO_THRESHOLD})")
                            
                            logger.debug(f"Advanced analysis for {path}: max_window_entropy={max_window_entropy}, "
                                        f"high_entropy_windows={high_entropy_windows}, diff_area={diff_area}, "
                                        f"change_ratio={change_ratio:.2f}, patterns={pattern_detection_results}")
                        
                        if current_entropy is None:  # Error during calculation or too small and skipped
                            logger.warning(f"Could not calculate or skipped entropy for {path}. Event: {event_type}")
                            # If it was a rename to encrypted, this is still very suspicious
                            if event_type == "renamed_target_to_encrypted" or event_type == "renamed_to_encrypted":
                                suspicious_messages.append(f"File renamed from {original_path} to {path}. New file unreadable/too small for entropy.")
                                self._update_suspicious_activity_log(path, event_type, {"original_path": original_path, "new_path": path, "error": "unreadable/too small"}, is_high_risk=True)
                            return  # Stop processing if we can't analyze content
                else:
                    logger.warning(f"File {path} not found during event processing ({event_type}). It might have been deleted quickly.")
                    if event_type == "renamed_target_to_encrypted" or event_type == "renamed_to_encrypted":
                        suspicious_messages.append(f"File renamed from {original_path} to {path}, then {path} was deleted before analysis.")
                        self._update_suspicious_activity_log(path, f"{event_type}_then_deleted", {"original_path": original_path, "new_path": path}, is_high_risk=True)
                    return
            except Exception as e:
                logger.error(f"Error during initial content analysis for {path} ({event_type}): {e}")
                return

        # Determine the key for baseline lookup. If renamed, original_path is the key.
        baseline_key_lookup = original_path if original_path else path
        prev_baseline = self.baselines.get(baseline_key_lookup)

        # --- Main Detection Logic ---

        # Check for advanced encryption indicators
        is_encrypted_by_window = max_window_entropy is not None and max_window_entropy >= SLIDING_WINDOW_ENTROPY_THRESHOLD and high_entropy_windows > 0
        is_encrypted_by_diff_area = diff_area is not None and diff_area < DIFFERENTIAL_AREA_THRESHOLD
        is_encrypted_by_entropy = current_entropy is not None and current_entropy >= HIGH_ENTROPY_THRESHOLD
        is_encrypted_by_pattern = bool(pattern_detection_results.get('binary_content', False) or 
                                     any(k.startswith('encryption_') for k in pattern_detection_results.keys()))
        is_hashed_by_pattern = any(k.startswith('hash_') for k in pattern_detection_results.keys())
        is_high_change_ratio = change_ratio >= CHANGE_RATIO_THRESHOLD

        # Combine detection methods for stronger confidence
        is_likely_encrypted = (is_encrypted_by_entropy or is_encrypted_by_window or 
                             is_encrypted_by_diff_area or is_encrypted_by_pattern)
        
        # Prepare a summary of detection methods that triggered alerts
        detection_methods = []
        if is_encrypted_by_entropy:
            detection_methods.append(f"High overall entropy ({current_entropy:.2f} bits/byte)")
        if is_encrypted_by_window:
            detection_methods.append(f"High sliding-window entropy ({max_window_entropy:.2f} bits/byte in {high_entropy_windows} windows)")
        if is_encrypted_by_diff_area:
            detection_methods.append(f"Low differential area ({diff_area:.2f} bit-bytes)")
        if is_high_change_ratio:
            detection_methods.append(f"High change ratio ({change_ratio:.2f})")
        if is_hashed_by_pattern:
            hash_types = [k.replace('hash_', '') for k in pattern_detection_results.keys() if k.startswith('hash_')]
            detection_methods.append(f"Hash pattern(s) detected: {', '.join(hash_types)}")
        if is_encrypted_by_pattern:
            enc_types = [k.replace('encryption_', '') for k in pattern_detection_results.keys() if k.startswith('encryption_')]
            if pattern_detection_results.get('binary_content', False):
                enc_types.append('binary_content')
            if enc_types:
                detection_methods.append(f"Encryption pattern(s) detected: {', '.join(enc_types)}")

        # Determine event significance based on combined factors
        if pattern_detection_results.get('binary_content', False):
            is_high_risk_event = True
            
        if is_high_change_ratio:
            suspicious_messages.append(f"High change ratio detected: {change_ratio:.2f} (threshold: {CHANGE_RATIO_THRESHOLD})")
            # Only mark as high risk if combined with other indicators
            if is_likely_encrypted or is_hashed_by_pattern:
                is_high_risk_event = True

        if detection_methods:
            logger.info(f"Detection methods for {path}: {'; '.join(detection_methods)}")

        if event_type == "created":
            is_high_risk_event = False
            if is_encrypted_file_type:
                suspicious_messages.append(f"Newly created file with known ENCRYPTED extension: {path}")
                if is_likely_encrypted:
                    suspicious_messages.append(f"Encryption indicators detected: {'; '.join(detection_methods)}")
                    is_high_risk_event = True
                else:
                    entropy_str = f"{current_entropy:.2f}" if current_entropy is not None else "N/A"
                    suspicious_messages.append(f"Entropy indicators not above thresholds, but extension is suspicious.")
                self._update_suspicious_activity_log(path, "created_encrypted_extension", {
                    "entropy": current_entropy, 
                    "hash": current_hash[:8] if current_hash else 'N/A',
                    "max_window_entropy": max_window_entropy,
                    "high_entropy_windows": high_entropy_windows,
                    "diff_area": diff_area,
                    "patterns": pattern_detection_results
                }, is_high_risk=is_high_risk_event)
            elif is_target_file and current_hash and current_entropy is not None:
                self.baselines[path] = {
                    'hash': current_hash, 
                    'entropy': current_entropy, 
                    'content': file_content,
                    'max_window_entropy': max_window_entropy,
                    'high_entropy_windows': high_entropy_windows,
                    'diff_area': diff_area,
                    'last_event': event_type, 
                    'is_target': True
                }
                logger.info(f"Established baseline for new TARGET file: {path} (Hash: {current_hash[:8]}, Entropy: {current_entropy:.2f})")
                
                # Check if new file appears to be encrypted or hashed from the start
                if is_likely_encrypted or is_hashed_by_pattern:
                    suspicious_messages.append(f"New TARGET file contains suspicious content: {'; '.join(detection_methods)}")
                    self._update_suspicious_activity_log(path, "created_suspicious_target", {
                        "detection_methods": detection_methods,
                        "patterns": pattern_detection_results
                    }, is_high_risk=True)
            # else: some other file type created, currently not baselined unless it's a target.

        elif event_type == "modified":
            is_high_risk_event = False
            if is_target_file and current_hash and current_entropy is not None:
                if prev_baseline and prev_baseline['hash'] == current_hash:
                    logger.info(f"TARGET file {path} modified but content hash is unchanged.")
                    # Update baseline with new entropy/event type if needed, though hash implies no change
                    self.baselines[path] = {
                        'hash': current_hash, 
                        'entropy': current_entropy,
                        'content': file_content,
                        'max_window_entropy': max_window_entropy,
                        'high_entropy_windows': high_entropy_windows,
                        'diff_area': diff_area,
                        'last_event': event_type, 
                        'is_target': True
                    }
                    # return # No need to log as suspicious if hash is same
                else:  # Hash changed or no previous baseline
                    if is_likely_encrypted or is_hashed_by_pattern or is_high_change_ratio:
                        suspicious_messages.append(f"TARGET file {path} modified with suspicious indicators:")
                        suspicious_messages.append(f"Detection methods: {'; '.join(detection_methods)}")
                        
                        if prev_baseline:
                            prev_entropy_str = f"{prev_baseline['entropy']:.2f}" if prev_baseline['entropy'] is not None else "N/A"
                            suspicious_messages.append(f"Previous entropy: {prev_entropy_str}, Previous hash: {prev_baseline.get('hash', 'N/A')[:8]}.")
                        
                        is_high_risk_event = True
                        alert_type = "modified_target_suspicious"
                        
                        if is_hashed_by_pattern:
                            alert_type = "hash_pattern_detected"
                            logger.warning(f"ALERT: Hash pattern detected in {path}: {detection_methods}")
                        elif is_likely_encrypted:
                            alert_type = "encryption_detected"
                            logger.warning(f"ALERT: Encryption detected in {path}: {detection_methods}")
                        elif is_high_change_ratio:
                            alert_type = "high_change_ratio"
                            
                        self._update_suspicious_activity_log(path, alert_type, 
                                                           {
                                                               "entropy": current_entropy, 
                                                               "prev_entropy": prev_baseline.get('entropy', 'N/A') if prev_baseline else 'N/A',
                                                               "hash": current_hash[:8], 
                                                               "prev_hash": prev_baseline.get('hash', 'N/A')[:8] if prev_baseline else 'N/A',
                                                               "max_window_entropy": max_window_entropy,
                                                               "high_entropy_windows": high_entropy_windows,
                                                               "diff_area": diff_area,
                                                               "change_ratio": change_ratio,
                                                               "patterns": pattern_detection_results,
                                                               "detection_methods": detection_methods
                                                           },
                                                           is_high_risk=True)
                    else:  # No concerning indicators, but hash changed
                         suspicious_messages.append(f"TARGET file {path} modified. No encryption/hash indicators, but content changed.")
                         if prev_baseline:
                            suspicious_messages.append(f"Previous hash: {prev_baseline.get('hash', 'N/A')[:8]}.")
                    # Update baseline for the target file
                    self.baselines[path] = {
                        'hash': current_hash, 
                        'entropy': current_entropy,
                        'content': file_content,
                        'max_window_entropy': max_window_entropy,
                        'high_entropy_windows': high_entropy_windows,
                        'diff_area': diff_area,
                        'last_event': event_type, 
                        'is_target': True
                    }
                    logger.info(f"Updated baseline for modified TARGET file: {path} (Hash: {current_hash[:8]}, Entropy: {current_entropy:.2f})")
            elif is_encrypted_file_type:  # Modification of an already encrypted file type
                suspicious_messages.append(f"Known ENCRYPTED file type {path} was modified. This is unusual.")
                # We might not have a baseline hash for these if they were created as .enc
                # but if we do, check it.
                if prev_baseline and prev_baseline.get('hash') != current_hash:
                     suspicious_messages.append(f"Content hash changed from {prev_baseline.get('hash', 'N/A')[:8]} to {current_hash[:8] if current_hash else 'N/A'}.")
                is_high_risk_event = True  # Modifying an already encrypted file is suspicious
                self._update_suspicious_activity_log(path, "modified_known_encrypted", {
                    "hash": current_hash[:8] if current_hash else 'N/A', 
                    "prev_hash": prev_baseline.get('hash', 'N/A')[:8] if prev_baseline else 'N/A', 
                    "entropy": current_entropy,
                    "max_window_entropy": max_window_entropy,
                    "high_entropy_windows": high_entropy_windows,
                    "diff_area": diff_area,
                    "patterns": pattern_detection_results,
                    "detection_methods": detection_methods if detection_methods else []
                }, is_high_risk=True)
                if current_hash and current_entropy is not None:  # Update baseline if it makes sense
                    self.baselines[path] = {
                        'hash': current_hash, 
                        'entropy': current_entropy,
                        'content': file_content,
                        'max_window_entropy': max_window_entropy,
                        'high_entropy_windows': high_entropy_windows,
                        'diff_area': diff_area,
                        'last_event': event_type, 
                        'is_target': False, 
                        'is_encrypted_type': True
                    }

        elif event_type == "renamed_target_to_encrypted":  # e.g. mydoc.txt -> mydoc.txt.enc
            is_high_risk_event = True
            suspicious_messages.append(f"CRITICAL: TARGET file {original_path} RENAMED to ENCRYPTED file {path}.")
            if is_likely_encrypted:
                suspicious_messages.append(f"Encryption indicators in new file {path}:")
                suspicious_messages.append(f"{'; '.join(detection_methods)}")
            elif current_entropy is not None:
                suspicious_messages.append(f"Entropy indicators for new file {path} are not above thresholds, but rename is primary indicator.")
            else:  # current_entropy is None (error/too small)
                suspicious_messages.append(f"Could not determine entropy for {path}, but rename itself is highly suspicious.")

            self._update_suspicious_activity_log(path, event_type, 
                                               {
                                                   "original_path": original_path, 
                                                   "new_path": path, 
                                                   "new_entropy": current_entropy,
                                                   "max_window_entropy": max_window_entropy,
                                                   "high_entropy_windows": high_entropy_windows,
                                                   "diff_area": diff_area,
                                                   "change_ratio": change_ratio,
                                                   "new_hash": current_hash[:8] if current_hash else 'N/A',
                                                   "original_baseline": prev_baseline,
                                                   "patterns": pattern_detection_results,
                                                   "detection_methods": detection_methods if detection_methods else []
                                               },
                                               is_high_risk=True)
            if original_path in self.baselines: del self.baselines[original_path]
            # Add new baseline for the .enc file, it might be modified/deleted later
            if current_hash and current_entropy is not None:
                 self.baselines[path] = {
                     'hash': current_hash, 
                     'entropy': current_entropy,
                     'content': file_content,
                     'max_window_entropy': max_window_entropy,
                     'high_entropy_windows': high_entropy_windows,
                     'diff_area': diff_area,
                     'last_event': event_type, 
                     'original_path': original_path, 
                     'is_target': False, 
                     'is_encrypted_type': True
                 }

        elif event_type == "renamed_to_encrypted":  # e.g. unknown.dat -> unknown.dat.enc (original was not a target)
            is_high_risk_event = True  # Still high risk
            suspicious_messages.append(f"File {original_path} RENAMED to ENCRYPTED file {path}.")
            if is_likely_encrypted:
                suspicious_messages.append(f"Encryption indicators in new file {path}:")
                suspicious_messages.append(f"{'; '.join(detection_methods)}")
            elif current_entropy is not None:
                suspicious_messages.append(f"Entropy indicators for new file {path} are not above thresholds.")
            
            self._update_suspicious_activity_log(path, event_type, 
                                               {
                                                   "original_path": original_path, 
                                                   "new_path": path, 
                                                   "new_entropy": current_entropy,
                                                   "max_window_entropy": max_window_entropy,
                                                   "high_entropy_windows": high_entropy_windows,
                                                   "diff_area": diff_area,
                                                   "change_ratio": change_ratio,
                                                   "new_hash": current_hash[:8] if current_hash else 'N/A',
                                                   "patterns": pattern_detection_results,
                                                   "detection_methods": detection_methods if detection_methods else []
                                               },
                                               is_high_risk=True)
            if original_path in self.baselines: del self.baselines[original_path]  # If it happened to be baselined
            if current_hash and current_entropy is not None:
                 self.baselines[path] = {
                     'hash': current_hash, 
                     'entropy': current_entropy,
                     'content': file_content,
                     'max_window_entropy': max_window_entropy,
                     'high_entropy_windows': high_entropy_windows,
                     'diff_area': diff_area,
                     'last_event': event_type, 
                     'original_path': original_path, 
                     'is_target': False, 
                     'is_encrypted_type': True
                 }

        elif event_type == "deleted_target":
            is_high_risk_event = True  # Deletion of a target file is suspicious in context of other events
            suspicious_messages.append(f"TARGET file {path} was DELETED.")
            if prev_baseline:
                suspicious_messages.append(f"Previous baseline existed (Hash: {prev_baseline.get('hash', 'N/A')[:8]}, Entropy: {prev_baseline.get('entropy', 'N/A'):.2f}).")
            self._update_suspicious_activity_log(path, event_type, {"original_path_details": prev_baseline}, is_high_risk=True)
            if path in self.baselines: del self.baselines[path]

        elif event_type == "deleted_target_renamed_other":  # e.g. mydoc.txt -> mydoc.bak, original .txt is "deleted"
            is_high_risk_event = True  # Potentially, as it's loss of a target file
            suspicious_messages.append(f"TARGET file {original_path} was effectively DELETED by renaming to {path}.")
            if prev_baseline:  # prev_baseline here refers to original_path
                suspicious_messages.append(f"Original baseline (Hash: {prev_baseline.get('hash', 'N/A')[:8]}, Entropy: {prev_baseline.get('entropy', 'N/A'):.2f}).")
            self._update_suspicious_activity_log(original_path, event_type, {"original_path": original_path, "new_path": path, "original_baseline": prev_baseline}, is_high_risk=True)
            if original_path in self.baselines: del self.baselines[original_path]
            # We are not creating a baseline for 'path' here unless it's a target itself, handled by "renamed_to_target"

        elif event_type == "deleted_encrypted":
            logger.info(f"Known ENCRYPTED file {path} was deleted. This might be cleanup by attacker or user.")
            if path in self.baselines: del self.baselines[path]
        
        elif event_type == "deleted_unknown":
            logger.info(f"Non-target/non-encrypted (or unknown to handler) file {path} deleted.")
            if path in self.baselines:  # Unlikely unless it was a renamed target previously
                del self.baselines[path]

        elif event_type == "renamed_to_target":  # e.g. temp.tmp -> mydoc.txt
            suspicious_messages.append(f"File {original_path} was RENAMED to a TARGET file type: {path}.")
            if current_hash and current_entropy is not None:
                existing_baseline_for_dest = self.baselines.get(path)
                if existing_baseline_for_dest and existing_baseline_for_dest['hash'] == current_hash:
                    logger.info(f"Content of new target file {path} matches its previous baseline. No change.")
                elif is_likely_encrypted or is_hashed_by_pattern:
                     suspicious_messages.append(f"New TARGET file {path} has suspicious indicators. Suspicious if replacing legitimate file.")
                     suspicious_messages.append(f"{'; '.join(detection_methods)}")
                     is_high_risk_event = True
                     self._update_suspicious_activity_log(path, "renamed_to_target_high_entropy",
                                                        {
                                                            "original_path": original_path, 
                                                            "new_entropy": current_entropy,
                                                            "max_window_entropy": max_window_entropy,
                                                            "high_entropy_windows": high_entropy_windows,
                                                            "diff_area": diff_area,
                                                            "change_ratio": change_ratio,
                                                            "new_hash": current_hash[:8] if current_hash else 'N/A',
                                                            "patterns": pattern_detection_results,
                                                            "detection_methods": detection_methods
                                                        }, is_high_risk=True)

                self.baselines[path] = {
                    'hash': current_hash, 
                    'entropy': current_entropy,
                    'content': file_content,
                    'max_window_entropy': max_window_entropy,
                    'high_entropy_windows': high_entropy_windows,
                    'diff_area': diff_area,
                    'last_event': event_type, 
                    'original_path': original_path, 
                    'is_target': True
                }
                logger.info(f"Baseline updated/established for new TARGET file {path} (from {original_path}) (Hash: {current_hash[:8]}, Entropy: {current_entropy:.2f})")
            if original_path in self.baselines: del self.baselines[original_path]

        elif event_type == "renamed_encrypted_to_encrypted":  # e.g. file.enc -> file.locked
            suspicious_messages.append(f"ENCRYPTED file {original_path} RENAMED to another ENCRYPTED file {path}.")
            is_high_risk_event = True
            self._update_suspicious_activity_log(path, event_type,
                                               {
                                                   "original_path": original_path, 
                                                   "new_path": path, 
                                                   "new_entropy": current_entropy,
                                                   "max_window_entropy": max_window_entropy,
                                                   "high_entropy_windows": high_entropy_windows,
                                                   "diff_area": diff_area,
                                                   "new_hash": current_hash[:8] if current_hash else 'N/A',
                                                   "patterns": pattern_detection_results,
                                                   "detection_methods": detection_methods if detection_methods else []
                                               },
                                               is_high_risk=True)
            if original_path in self.baselines: del self.baselines[original_path]
            if current_hash and current_entropy is not None:
                 self.baselines[path] = {
                     'hash': current_hash, 
                     'entropy': current_entropy,
                     'content': file_content,
                     'max_window_entropy': max_window_entropy,
                     'high_entropy_windows': high_entropy_windows,
                     'diff_area': diff_area,
                     'last_event': event_type, 
                     'original_path': original_path, 
                     'is_target': False, 
                     'is_encrypted_type': True
                 }

        if suspicious_messages:
            summary_message = f'Suspicious activity for "{path}" (Event: {event_type}): {"; ".join(suspicious_messages)}'
            if is_high_risk_event:
                 logger.warning(summary_message)
            else:
                logger.info(summary_message)

        elif is_target_file and event_type not in ["deleted_target", "deleted_encrypted", "deleted_unknown", "deleted_target_renamed_other"] and current_hash and current_entropy is not None:
            if not prev_baseline or prev_baseline.get('hash') != current_hash:
                if path not in self.baselines or self.baselines[path].get('hash') != current_hash:
                    self.baselines[path] = {
                        'hash': current_hash, 
                        'entropy': current_entropy,
                        'content': file_content,
                        'max_window_entropy': max_window_entropy,
                        'high_entropy_windows': high_entropy_windows,
                        'diff_area': diff_area,
                        'last_event': event_type, 
                        'is_target': True
                    }
                    logger.info(f"General baseline update/established for TARGET {path} (Event: {event_type}, Hash: {current_hash[:8]}, Entropy: {current_entropy:.2f})")
        
        if not is_high_risk_event and event_type not in ["deleted_encrypted", "deleted_unknown"]:
            self._update_activity_rates(is_encryption_like=False)
