#!/usr/bin/env python3
"""
Ransomware Monitor - Testing Tools Script

This script provides access to various testing tools for the ransomware monitor.
It allows you to generate test files, encrypt files, decrypt files, and more.

Usage:
    python test_tools.py list                       # List available test tools
    python test_tools.py generate_test_files        # Generate test text files
    python test_tools.py encrypt_files              # Encrypt test files
    python test_tools.py decrypt_files              # Decrypt files
    python test_tools.py hash_txt_files             # Hash text files
    python test_tools.py folder_encryptor encrypt <dir>  # Encrypt all files in a directory
    python test_tools.py folder_encryptor decrypt <dir>  # Decrypt all files in a directory
"""

import os
import sys
import subprocess
import importlib.util

# Add the current directory to the path to ensure imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Define paths
TESTING_TOOLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testing_tools")
TEXT_FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "txt_for_testing")

def list_testing_tools():
    """List all available testing tools"""
    print("Available Testing Tools:")
    
    if not os.path.exists(TESTING_TOOLS_DIR):
        print(f"Error: Testing tools directory not found at {TESTING_TOOLS_DIR}")
        return
        
    tools = [f.replace('.py', '') for f in os.listdir(TESTING_TOOLS_DIR) 
             if f.endswith('.py') and not f.startswith('__')]
    
    # Standard tools
    print("\nStandard Tools:")
    standard_tools = ['generate_test_files', 'encrypt_files', 'decrypt_files', 'hash_txt_files']
    for tool in standard_tools:
        if tool in tools:
            print(f"  - {tool}")
            tools.remove(tool)
    
    # Special tools with arguments
    print("\nSpecial Tools:")
    if 'folder_encryptor' in tools:
        print("  - folder_encryptor encrypt <directory>  # Encrypt all files in a directory")
        print("  - folder_encryptor decrypt <directory>  # Decrypt all files in a directory")
        tools.remove('folder_encryptor')
    
    # Other tools
    if tools:
        print("\nOther Tools:")
        for tool in tools:
            print(f"  - {tool}")
    
    print("\nUsage examples:")
    print("  python test_tools.py generate_test_files")
    print("  python test_tools.py encrypt_files")
    print("  python test_tools.py folder_encryptor encrypt txt_for_testing")

def run_testing_tool(tool_name, args=None):
    """Run a specific testing tool"""
    # Handle folder_encryptor specially since it needs arguments
    if tool_name == 'folder_encryptor' and args and len(args) >= 2:
        mode = args[0]
        directory = args[1]
        if mode not in ['encrypt', 'decrypt']:
            print(f"Error: folder_encryptor mode must be 'encrypt' or 'decrypt', got '{mode}'")
            return
        
        tool_path = os.path.join(TESTING_TOOLS_DIR, f"{tool_name}.py")
        if not os.path.exists(tool_path):
            print(f"Error: Testing tool '{tool_name}' not found at {tool_path}")
            return
            
        print(f"Running {tool_name} {mode} on directory: {directory}")
        
        cmd = [sys.executable, tool_path, mode, directory]
        try:
            result = subprocess.run(cmd, cwd=os.path.dirname(os.path.abspath(__file__)))
            if result.returncode != 0:
                print(f"Warning: Tool exited with code {result.returncode}")
        except Exception as e:
            print(f"Error executing {tool_name}: {e}")
        return
        
    # Handle standard tools that don't require arguments
    if tool_name.endswith('.py'):
        tool_name = tool_name[:-3]  # Remove .py extension if provided
        
    tool_path = os.path.join(TESTING_TOOLS_DIR, f"{tool_name}.py")
    
    if not os.path.exists(tool_path):
        print(f"Error: Testing tool '{tool_name}' not found at {tool_path}")
        print("\nAvailable tools:")
        list_testing_tools()
        return
    
    print(f"Running testing tool: {tool_name}")
    
    # Use subprocess to execute the script directly
    cmd = [sys.executable, tool_path]
    if args:
        cmd.extend(args)
        
    try:
        result = subprocess.run(cmd, cwd=os.path.dirname(os.path.abspath(__file__)))
        if result.returncode != 0:
            print(f"Warning: Tool exited with code {result.returncode}")
    except Exception as e:
        print(f"Error executing {tool_name}: {e}")

def show_help():
    """Show help message"""
    print(__doc__)
    print("\nAvailable tools:")
    list_testing_tools()
        
if __name__ == "__main__":
    if len(sys.argv) < 2:
        show_help()
        sys.exit(1)
        
    command = sys.argv[1]
    
    if command == "list":
        list_testing_tools()
    elif command == "help":
        show_help()
    elif command == "folder_encryptor" and len(sys.argv) >= 4:
        run_testing_tool(command, [sys.argv[2], sys.argv[3]])
    else:
        run_testing_tool(command, sys.argv[2:] if len(sys.argv) > 2 else None)