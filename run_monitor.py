#!/usr/bin/env python3
"""
Ransomware Monitor - Launcher Script

This script provides an easy way to launch the ransomware monitoring system.
It simply runs the main monitoring functionality as defined in core/main.py.

Usage:
    python run_monitor.py  # Run the ransomware monitoring system

Performance Metrics:
    - Memory Usage: O(n × m) where n = number of files, m = avg file size
      Stores file contents, hashes, entropy values, and event history.
    
    - Runtime Complexity: O(n) 
      Linear processing of file events and content analysis.
    
    - I/O Complexity: Low
      Uses OS event notifications instead of periodic polling.
"""

import os
import sys
import subprocess

# Define core directory path
CORE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "core")

def run_monitor():
    """Run the main monitoring system"""
    print("Starting Ransomware Monitor...")
    try:
        # Change directory to core and run main.py directly
        # This avoids import issues with relative/absolute imports
        main_script = os.path.join(CORE_DIR, "main.py")
        
        # Execute the main.py script directly
        subprocess.run([sys.executable, main_script], cwd=CORE_DIR)
    except Exception as e:
        print(f"Error running monitor: {e}")
        import traceback
        traceback.print_exc()
        
if __name__ == "__main__":
    run_monitor()