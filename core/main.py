"""
Ransomware Monitor - Main Entry Point

Performance:
    - Memory Usage: O(1) - This script only maintains path variables
    - Runtime Complexity: O(1) - Simple setup with constant-time operations
    - I/O Complexity: Low - Only reads user input, no file scanning

Purpose:
This script is the main entry point for the ransomware detection monitor.
It prompts the user to enter a directory path that they want to monitor.
Once a valid directory is provided, it starts monitoring that directory for
suspicious file activities typically associated with ransomware (e.g., rapid
encryption of multiple files).

How to Run:
1. Ensure you have Python installed.
2. Navigate to the script's directory in your terminal.
3. Run the script using the command: python main.py
4. When prompted, enter the full path to the folder you wish to monitor.
   Example: /Users/yourusername/Documents/ImportantFiles

Dependencies:
- monitor.py (and its dependencies)
"""
import os
import sys
import monitor  # Using absolute import since we're running the file directly
from config import MAIN_DIR  # Import the main directory path

def main():
    # Change working directory to the main project directory
    os.chdir(MAIN_DIR)
    
    # Now when we prompt for input, paths will be relative to the main directory
    watched = input("Enter the full path of the folder to monitor for ransomware: ")
    
    # Convert to absolute path if it's not already
    if not os.path.isabs(watched):
        watched = os.path.abspath(watched)
        
    if not os.path.isdir(watched):
        print(f'Path not found or not a directory: {watched}')
        return
        
    monitor_instance = monitor.DirectoryMonitor(watched)
    monitor_instance.start()
    print(f"Monitoring directory: {watched}")

if __name__ == '__main__':
    main()
