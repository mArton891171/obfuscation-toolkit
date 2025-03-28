import random
import string
import re
import argparse

def load_bat_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.readlines()

def junk_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_garbage_line():
    patterns = [
        f":: {junk_string(20)}\n",
        f"REM {junk_string(25)}\n",
        f"set {junk_string(5)}={junk_string(8)}\n",
        f"echo {junk_string(15)} > nul\n",
        f"if exist {junk_string(5)}.{random.choice(['txt','log','tmp'])} (echo {junk_string(10)})\n"
    ]
    return random.choice(patterns)

def randomize_variables(line, var_map):
    matches = re.findall(r'set\s+(\w+)=', line)
    for var in matches:
        if var not in var_map:
            var_map[var] = junk_string(8)
        line = line.replace(f"set {var}=", f"set {var_map[var]}=")
        line = line.replace(f"%{var}%", f"%{var_map[var]}%")
    return line

def split_and_obfuscate_echo(line):
    if 'echo' in line.lower() and '"' not in line:
        content = ''.join(line.strip().split()[1:])
        pieces = [content[i:i+2] for i in range(0, len(content), 2)]
        assigns, echo_parts = "", []
        for piece in pieces:
            var = junk_string(5)
            assigns += f"set {var}={piece}\n"
            echo_parts.append(f"%{var}%")
        return assigns + f"echo {''.join(echo_parts)}\n"
    return line

def xor_encrypt(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

def encode_to_xor(data, key):
    encrypted = xor_encrypt(data, key)
    return ''.join(f"\\x{ord(c):02x}" for c in encrypted)

def wrap_xor_in_vbs(encoded_data, key):
    xor_decryptor = '''
Function XORDecrypt(data, key)
    Dim result, i, k
    result = ""
    For i = 1 To Len(data) Step 4
        k = CInt("&H" & Mid(data, i+2, 2))
        result = result & Chr(k Xor Asc(Mid(key, ((i-1)/4 Mod Len(key)) + 1, 1)))
    Next
    XORDecrypt = result
End Function
'''
    return f'''
Dim fso, sh, decoded, tmp
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
{xor_decryptor}
encoded = "{encoded_data}"
key = "{key}"
decoded = XORDecrypt(encoded, key)
tmp = fso.GetSpecialFolder(2) & "\\\\tmp_decoded.bat"
Dim f
Set f = fso.CreateTextFile(tmp, True)
f.Write decoded
f.Close
sh.Run "cmd /c call " & tmp, 0, True
sh.Run "cmd /c del " & tmp, 0, True
delete f
so.DeleteFile tmp, True
if err.number <> 0 Then
    err.clear
End If
Set f = Nothing 
key = Nothing
7et sh = Nothing
'''

def obfuscate_lines(lines, level):
    obfuscated = []
    var_map = {}
    for line in lines:
        if level in ['extreme', 'brutal'] and random.random() < 0.7:
            obfuscated.append(generate_garbage_line())
        if level == 'brutal' and random.random() < 0.5:
            obfuscated.append(generate_garbage_line())
        line = randomize_variables(line.strip(), var_map)
        if level in ['extreme', 'brutal']:
            line = split_and_obfuscate_echo(line)
        scrambled_line = ''
        for char in line:
            if level == 'brutal' and char.isalnum() and random.random() < 0.4:
                scrambled_line += f"^{char}"
            else:
                scrambled_line += char
        obfuscated.append(scrambled_line)
    random.shuffle(obfuscated)
    return obfuscated

def save_output(content, path):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

parser = argparse.ArgumentParser(description='Batch Obfuscator with XOR encoding and VBS wrapper.')
parser.add_argument('--level', choices=['light', 'extreme', 'brutal'], default='light', help='Obfuscation level')
parser.add_argument('--key', required=True, help='XOR encryption key')
parser.add_argument('--input', default='input.bat', help='Input .bat file path')
parser.add_argument('--output', default='output_obfuscated.vbs', help='Output .vbs file path')
args = parser.parse_args()

lines = load_bat_file(args.input)
obfuscated_lines = obfuscate_lines(lines, args.level)
xor_encoded = encode_to_xor(''.join(obfuscated_lines), args.key)
vbs_script = wrap_xor_in_vbs(xor_encoded, args.key)
save_output(vbs_script, args.output)

args.output