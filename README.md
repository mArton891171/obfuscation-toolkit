
# 🔥 ObfuKiller – Ultimate Batch & VBS Obfuscation Toolkit

> 👁️‍🗨️ Make scripts unreadable to humans – fully executable by machines.

---

## 🎯 What is ObfuKiller?

ObfuKiller is a dual-script obfuscation engine for `.bat` and `.vbs` files.  
It transforms clean scripts into unreadable chaos using randomization, XOR encoding, string fragmentation, and aggressive junk insertion.

Perfect for:

- ✅ Red Team labs
- ✅ Malware simulation
- ✅ Payload wrapping
- ✅ Anti-reversing training

> ⚠️ **FOR EDUCATIONAL & RESEARCH PURPOSES ONLY**

---

## ⚙️ Features

### 🧠 `bat_obfuscator.py`

- Multi-level obfuscation: `--light`, `--extreme`, `--brutal`
- XOR encryption of .bat content
- Auto VBS wrapper generation
- Random junk lines, `echo` string-splitting, var renaming

#### Example usage:
```bash
python bat_obfuscator.py --input input.bat --output output.vbs --level brutal --key (your key)
```

---

### 💀 `vbs_obfuscator.py`

- Obfuscates any existing `.vbs` file
- Minimum 30+ lines guaranteed
- Random comments, fake logic, full charset variable names (a-z, A-Z, 0-9, symbols)
- Strings split into `"c" & "m" & "d"`-style fragments

#### Example usage:
```bash
python vbs_obfuscator.py --input output.vbs --output output_obfuscated.vbs
```

---

## 📁 Structure

```
├── bat_obfuscator.py           # .bat → XOR → .vbs
├── vbs_obfuscator.py           # .vbs → obfuscated
├── input.bat                   # Your input .bat
├── output.vbs                  # XOR'd + wrapped VBS
├── output_obfuscated.vbs       # Final obfuscated result
```

---

## ✅ Requirements

- Python 3.x
- No dependencies

---

## ⚠️ Legal Notice

This project is intended **for educational, testing, and research purposes only**.  
Any misuse of this code is strictly your own responsibility.  
**Don't be evil.**

---

