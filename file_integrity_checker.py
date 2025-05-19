#!/usr/bin/env python3
"""
File Integrity Checker

This script monitors files for changes by calculating and comparing hash values.
It can:
1. Generate a database of file hashes
2. Verify files against the database
3. Monitor files continuously for changes
4. Generate reports of file modifications

Author: CodeTech Intern
"""

import os
import sys
import time
import json
import hashlib
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional


class FileIntegrityChecker:
    """Main class for file integrity checking and monitoring"""
    
    def __init__(self, database_path: str = "file_hashes.json"):
        """Initialize the file integrity checker with a database path"""
        self.database_path = database_path
        self.database = self._load_database()
        self.supported_hash_algorithms = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512
        }
        
    def _load_database(self) -> Dict:
        """Load existing hash database if it exists"""
        if os.path.exists(self.database_path):
            try:
                with open(self.database_path, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                print(f"Error: Database file {self.database_path} is corrupted. Creating a new database.")
                return {"files": {}, "metadata": {"last_updated": datetime.now().isoformat()}}
        else:
            return {"files": {}, "metadata": {"last_updated": datetime.now().isoformat()}}
    
    def _save_database(self) -> None:
        """Save the hash database to disk"""
        self.database["metadata"]["last_updated"] = datetime.now().isoformat()
        with open(self.database_path, 'w') as f:
            json.dump(self.database, f, indent=4)
        print(f"Database saved to {self.database_path}")
    
    def calculate_file_hash(self, file_path: str, algorithm: str = "sha256") -> Optional[str]:
        """Calculate the hash of a file using the specified algorithm"""
        if algorithm not in self.supported_hash_algorithms:
            print(f"Error: Unsupported hash algorithm '{algorithm}'")
            return None
        
        try:
            hash_obj = self.supported_hash_algorithms[algorithm]()
            
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files efficiently
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
                    
            return hash_obj.hexdigest()
        except Exception as e:
            print(f"Error calculating hash for {file_path}: {e}")
            return None
    
    def add_file(self, file_path: str, algorithm: str = "sha256") -> bool:
        """Add a file to the database with its current hash"""
        if not os.path.isfile(file_path):
            print(f"Error: {file_path} is not a valid file")
            return False
            
        abs_path = os.path.abspath(file_path)
        file_hash = self.calculate_file_hash(abs_path, algorithm)
        
        if file_hash:
            self.database["files"][abs_path] = {
                "hash": file_hash,
                "algorithm": algorithm,
                "last_verified": datetime.now().isoformat(),
                "size": os.path.getsize(abs_path),
                "last_modified": datetime.fromtimestamp(os.path.getmtime(abs_path)).isoformat()
            }
            return True
        return False
    
    def add_directory(self, directory_path: str, algorithm: str = "sha256", recursive: bool = True) -> Tuple[int, int]:
        """Add all files in a directory to the database"""
        if not os.path.isdir(directory_path):
            print(f"Error: {directory_path} is not a valid directory")
            return (0, 0)
        
        success_count = 0
        fail_count = 0
        
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                if self.add_file(file_path, algorithm):
                    success_count += 1
                else:
                    fail_count += 1
            
            # If not recursive, break after the first level
            if not recursive:
                break
                
        return (success_count, fail_count)
    
    def verify_file(self, file_path: str) -> Tuple[bool, str]:
        """Verify a file against its stored hash"""
        abs_path = os.path.abspath(file_path)
        
        if abs_path not in self.database["files"]:
            return (False, "File not in database")
        
        stored_data = self.database["files"][abs_path]
        current_hash = self.calculate_file_hash(abs_path, stored_data["algorithm"])
        
        if current_hash == stored_data["hash"]:
            # Update verification time
            self.database["files"][abs_path]["last_verified"] = datetime.now().isoformat()
            return (True, "File integrity verified")
        else:
            return (False, "File has been modified")
    
    def verify_all_files(self) -> Dict:
        """Verify all files in the database"""
        results = {
            "verified": 0,
            "modified": 0,
            "missing": 0,
            "errors": 0,
            "modified_files": [],
            "missing_files": []
        }
        
        for file_path in list(self.database["files"].keys()):
            if not os.path.exists(file_path):
                results["missing"] += 1
                results["missing_files"].append(file_path)
                continue
                
            try:
                is_verified, message = self.verify_file(file_path)
                if is_verified:
                    results["verified"] += 1
                else:
                    results["modified"] += 1
                    results["modified_files"].append(file_path)
            except Exception as e:
                results["errors"] += 1
                print(f"Error verifying file {file_path}: {e}")
                
        return results
    
    def monitor(self, interval: int = 60, report_file: str = None) -> None:
        """Monitor files continuously at specified intervals"""
        try:
            print(f"Starting continuous monitoring at {interval} second intervals...")
            print("Press Ctrl+C to stop monitoring")
            
            while True:
                print(f"\n[{datetime.now().isoformat()}] Running verification scan...")
                results = self.verify_all_files()
                
                print(f"  Verified: {results['verified']} files")
                
                if results["modified"] > 0:
                    print(f"  Modified: {results['modified']} files")
                    for file in results["modified_files"]:
                        print(f"    - {file}")
                        # Update the hash for the modified file
                        algorithm = self.database["files"][file]["algorithm"]
                        self.add_file(file, algorithm)
                
                if results["missing"] > 0:
                    print(f"  Missing: {results['missing']} files")
                    for file in results["missing_files"]:
                        print(f"    - {file}")
                        # Remove missing files from the database
                        del self.database["files"][file]
                
                if report_file:
                    self._append_to_report(results, report_file)
                
                # Save the updated database
                self._save_database()
                
                # Wait for the next interval
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
            self._save_database()
    
    def _append_to_report(self, results: Dict, report_file: str) -> None:
        """Append monitoring results to a report file"""
        timestamp = datetime.now().isoformat()
        
        report_entry = {
            "timestamp": timestamp,
            "results": results
        }
        
        # Create the report file if it doesn't exist
        if not os.path.exists(report_file):
            with open(report_file, 'w') as f:
                json.dump({"reports": [report_entry]}, f, indent=4)
        else:
            try:
                with open(report_file, 'r') as f:
                    report_data = json.load(f)
                
                report_data["reports"].append(report_entry)
                
                with open(report_file, 'w') as f:
                    json.dump(report_data, f, indent=4)
            except json.JSONDecodeError:
                print(f"Error: Report file {report_file} is corrupted. Creating a new file.")
                with open(report_file, 'w') as f:
                    json.dump({"reports": [report_entry]}, f, indent=4)
    
    def generate_report(self, output_file: str = "integrity_report.txt") -> None:
        """Generate a comprehensive report of the file database"""
        results = self.verify_all_files()
        
        with open(output_file, 'w') as f:
            f.write("File Integrity Report\n")
            f.write("===================\n\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Database: {self.database_path}\n")
            f.write(f"Total files: {len(self.database['files'])}\n\n")
            
            f.write("Summary\n")
            f.write("-------\n")
            f.write(f"Verified: {results['verified']} files\n")
            f.write(f"Modified: {results['modified']} files\n")
            f.write(f"Missing: {results['missing']} files\n")
            f.write(f"Errors: {results['errors']} files\n\n")
            
            if results["modified"] > 0:
                f.write("Modified Files\n")
                f.write("--------------\n")
                for file in results["modified_files"]:
                    f.write(f"- {file}\n")
                f.write("\n")
            
            if results["missing"] > 0:
                f.write("Missing Files\n")
                f.write("-------------\n")
                for file in results["missing_files"]:
                    f.write(f"- {file}\n")
                f.write("\n")
            
            f.write("All Files\n")
            f.write("---------\n")
            for file_path, file_data in self.database["files"].items():
                f.write(f"File: {file_path}\n")
                f.write(f"  Algorithm: {file_data['algorithm']}\n")
                f.write(f"  Hash: {file_data['hash']}\n")
                f.write(f"  Last Verified: {file_data['last_verified']}\n")
                f.write(f"  Last Modified: {file_data['last_modified']}\n")
                f.write(f"  Size: {file_data['size']} bytes\n\n")
        
        print(f"Report generated: {output_file}")

def main():
    """Main function to handle command line arguments"""
    parser = argparse.ArgumentParser(description="File Integrity Checker")
    
    # Create subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Add command parser
    add_parser = subparsers.add_parser("add", help="Add files to the database")
    add_parser.add_argument("path", help="File or directory path to add")
    add_parser.add_argument("--algorithm", "-a", default="sha256", choices=["md5", "sha1", "sha256", "sha512"], 
                          help="Hash algorithm to use")
    add_parser.add_argument("--recursive", "-r", action="store_true", help="Recursively add files in directories")
    add_parser.add_argument("--database", "-d", default="file_hashes.json", help="Database file path")
    
    # Verify command parser
    verify_parser = subparsers.add_parser("verify", help="Verify file integrity")
    verify_parser.add_argument("path", nargs="?", help="File path to verify (if not specified, verify all files)")
    verify_parser.add_argument("--database", "-d", default="file_hashes.json", help="Database file path")
    
    # Monitor command parser
    monitor_parser = subparsers.add_parser("monitor", help="Monitor files for changes")
    monitor_parser.add_argument("--interval", "-i", type=int, default=60, help="Monitoring interval in seconds")
    monitor_parser.add_argument("--report", "-r", help="Report file to append results to")
    monitor_parser.add_argument("--database", "-d", default="file_hashes.json", help="Database file path")
    
    # Report command parser
    report_parser = subparsers.add_parser("report", help="Generate a comprehensive report")
    report_parser.add_argument("--output", "-o", default="integrity_report.txt", help="Output file for the report")
    report_parser.add_argument("--database", "-d", default="file_hashes.json", help="Database file path")
    
    args = parser.parse_args()
    
    # Initialize the file integrity checker
    checker = FileIntegrityChecker(database_path=args.database if hasattr(args, "database") else "file_hashes.json")
    
    # Execute the specified command
    if args.command == "add":
        path = args.path
        if os.path.isfile(path):
            print(f"Adding file: {path}")
            success = checker.add_file(path, args.algorithm)
            if success:
                print(f"File added successfully: {path}")
                checker._save_database()
            else:
                print(f"Failed to add file: {path}")
        elif os.path.isdir(path):
            print(f"Adding directory: {path}")
            success, fail = checker.add_directory(path, args.algorithm, args.recursive)
            print(f"Added {success} files successfully, {fail} files failed")
            checker._save_database()
        else:
            print(f"Error: {path} is not a valid file or directory")
    
    elif args.command == "verify":
        if hasattr(args, "path") and args.path:
            print(f"Verifying file: {args.path}")
            success, message = checker.verify_file(args.path)
            print(f"Result: {message}")
        else:
            print("Verifying all files in database...")
            results = checker.verify_all_files()
            print(f"Verified: {results['verified']} files")
            print(f"Modified: {results['modified']} files")
            print(f"Missing: {results['missing']} files")
            print(f"Errors: {results['errors']} files")
            
            if results["modified"] > 0:
                print("\nModified files:")
                for file in results["modified_files"]:
                    print(f"- {file}")
            
            if results["missing"] > 0:
                print("\nMissing files:")
                for file in results["missing_files"]:
                    print(f"- {file}")
    
    elif args.command == "monitor":
        checker.monitor(interval=args.interval, report_file=args.report)
    
    elif args.command == "report":
        checker.generate_report(output_file=args.output)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()