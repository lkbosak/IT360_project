# IT360
# Memory Forensics Script
# Brandon Bui, Laura Bosakaite

#!/usr/bin/env python3
import subprocess
import pandas as pd
import matplotlib.pyplot as plt
import os
from typing import List, Dict

# Configuration
MEMORY_DUMP = "/home/vmuser/memory_forensics_project/data/cridex.vmem" # Specific memory path, needs to be updated each time
VOLATILITY_PATH = "/snap/bin/volatility"
OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Column definitions for different Volatility commands
COMMAND_COLUMNS = {
    "pslist": ["Offset", "Name", "PID", "PPID", "Threads", "Handles", "Time"],
    "psscan": ["Offset", "Name", "PID", "PPID", "Threads", "Handles", "Time"],
    "dlllist": ["PID", "Process", "Base", "Size", "Path"],
    "malfind": ["PID", "Process", "Start_Addr", "End_Addr", "Tag", "Protection"],
    "connscan": ["Offset", "Local_Address", "Remote_Address", "PID"],
    "filescan": ["Offset", "Pointer", "Hnd", "Access", "Name"]
}

def run_volatility(command: List[str]) -> str:
    """Execute Volatility command and return output"""
    try:
        result = subprocess.run(
            [VOLATILITY_PATH, "-f", MEMORY_DUMP] + command,
            capture_output=True, text=True
        )
        return result.stdout
    except FileNotFoundError:
        print(f"Error: Could not find Volatility at '{VOLATILITY_PATH}'")
        exit(1)

def parse_volatility_output(output: str, command: str) -> pd.DataFrame:
    """Parse Volatility output into DataFrame with dynamic column handling"""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    
    # Find header line (contains the command's expected columns)
    header_line = next((line for line in lines if any(col in line for col in COMMAND_COLUMNS[command])), None)
    
    if not header_line:
        print(f"No header found for command: {command}")
        return pd.DataFrame()
    
    # Get data lines (skip header and any divider lines)
    data_start = lines.index(header_line) + 1
    data_lines = [line.split() for line in lines[data_start:] if line and not line.startswith("---")]
    
    # Use predefined columns or generate dynamic ones
    if command in COMMAND_COLUMNS:
        columns = COMMAND_COLUMNS[command]
        # Take only the columns we expect (ignore extras)
        data = [line[:len(columns)] for line in data_lines]
    else:
        # Fallback for unknown commands
        columns = [f"Column_{i}" for i in range(len(data_lines[0]))]
        data = data_lines
    
    return pd.DataFrame(data, columns=columns)
#Extract .exe files from from file scan dump
def parsing_filescan_output(output: str, filter_exe: bool = False) -> pd.DataFrame:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    data = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 5:
            Offset = parts[0]
            Pointer = parts[1]
            Hnd = parts[2]
            Access = parts[3]
            Name = " ".join(parts[4:])
            if not filter_exe or ".exe" in Name.lower():
                data.append((Offset, Pointer, Hnd, Access, Name))
    return pd.DataFrame(data, columns=["Offset", "Pointer", "Hnd", "Access", "Name"])

def identify_profile() -> str:
    """Identify memory dump profile with fallback"""
    try:
        output = run_volatility(["imageinfo"])
        for line in output.splitlines():
            if "Suggested Profile(s)" in line:
                profile = line.split(":")[1].strip().split(",")[0].strip()
                print(f"Identified profile: {profile}")
                return profile
    except Exception as e:
        print(f"Profile detection failed: {str(e)}")
    
    # Common fallback profiles
    for profile in ["Win7SP1x64", "Win10x64_19041", "WinXPSP2x86"]:
        try:
            test_output = run_volatility(["--profile", profile, "pslist"])
            if "PID" in test_output:
                print(f"Using fallback profile: {profile}")
                return profile
        except:
            continue
    
    raise ValueError("Could not identify profile")

def analyze_memory(profile: str):
    """Run all analyses and save results"""
    analyses = {
        "processes": ("pslist", "processes.csv"),
        "hidden_processes": ("psscan", "hidden_processes.csv"),
        "dlls": ("dlllist", "dlls.csv"),
        "malware": ("malfind", "malware.csv"),
        "connections": ("connscan", "connections.csv"),
        "executable_files": ("filescan", "fileScan.csv")
    }
    
    results = {}
    for name, (command, filename) in analyses.items():
        print(f"Running {command}...")
        output = run_volatility(["--profile", profile, command])
        df = parse_volatility_output(output, command)
        if command == "filescan":
            df = parsing_filescan_output(output, filter_exe=True)
        else:
            df = parse_volatility_output(output, command)
        df.to_csv(os.path.join(OUTPUT_DIR, filename), index=False)
        results[name] = df
    
    return results

def visualize_results(results: Dict[str, pd.DataFrame]):
    """Create basic visualizations"""
    # Process count visualization [PLACEHOLDER, NEED TO ADD MORE]
    processes = results.get("processes")
    if processes is not None and not processes.empty:
        plt.figure(figsize=(10, 6))
        processes["Name"].value_counts().head(10).plot(kind="bar")
        plt.title("Top 10 Processes by Count")
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, "process_counts.png"))
        plt.close()

def generate_report(profile: str, results: Dict[str, pd.DataFrame]):
    """Generate summary report"""
    report = f"""
Memory Forensics Report
=======================
Profile: {profile}
Analysis Time: {pd.Timestamp.now()}

Summary Statistics:
------------------
- Processes: {len(results.get('processes', []))}
- Hidden Processes: {len(results.get('hidden_processes', []))}
- Network Connections: {len(results.get('connections', []))}
- Malware Findings: {len(results.get('malware', []))}
- Executable Files: {len(results.get('executable_files', []))}
"""
    with open(os.path.join(OUTPUT_DIR, "report.txt"), "w") as f:
        f.write(report)

if __name__ == "__main__":
    try:
        print("Starting memory analysis...")
        profile = identify_profile()
        results = analyze_memory(profile)
        visualize_results(results)
        generate_report(profile, results)
        print(f"Analysis complete. Results saved to: {OUTPUT_DIR}")
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
