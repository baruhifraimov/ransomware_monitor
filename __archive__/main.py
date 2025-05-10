"""
Ransomware Monitor - Main Entry Point

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
from monitor import DirectoryMonitor

def main():
    watched = input("Enter the full path of the folder to monitor for ransomware: ")
    if not os.path.isdir(watched):
        print(f'Path not found or not a directory: {watched}')
        return
    monitor = DirectoryMonitor(watched)
    monitor.start()
    print(f"Monitoring directory: {watched}")

if __name__ == '__main__':
    main()
