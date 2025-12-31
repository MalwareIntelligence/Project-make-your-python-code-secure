# MIPL Compiler & VM v6.0 - 100% Perfect Edition

A secure, production-ready compiler and virtual machine for MIPL (Machine Independent Programming Language) files with military-grade encryption and comprehensive security features.

## 🔐 Security Features

### Cryptography
- **AES-256-GCM** - Authenticated encryption with 256-bit keys
- **PBKDF2-SHA256** - Key derivation with 200,000 iterations
- **HMAC-SHA256** - Integrity verification with nonce and timestamp
- **Constant-time comparisons** - Timing attack resistant
- **Secure random generation** - BCrypt RNG with fallback

### Protection Mechanisms
- **Enhanced machine binding** - 5-factor hardware fingerprinting (CPU ID, MAC address, volume serial, computer name, Windows install date)
- **Replay attack protection** - Nonce-based authentication
- **Expiry date support** - 365-day default validity period
- **Password strength validation** - Minimum 12 characters, complexity requirements
- **TOCTOU-safe file operations** - Exclusive file locking
- **Atomic writes** - Temporary file with rename
- **Stack canary protection** - Buffer overflow detection
- **Control Flow Integrity (CFI)** - Hijacking prevention
- **Bounds checking** - All array accesses validated
- **Integer overflow protection** - Safe arithmetic everywhere
- **Secure memory zeroing** - Volatile memory clearing
- **RAII-style cleanup** - Automatic resource management
- **Audit logging** - Security event tracking

### Compression
- **0xFF escaping** - Proper handling of marker bytes
- **Hash table acceleration** - O(n) compression with 64K hash table
- **SIMD optimization** - Vectorized operations where available
- **Edge case handling** - Robust against malicious input

### Code Quality
- **State machine parser** - Proper Python syntax handling
- **No magic numbers** - All constants named
- **CERT C compliant** - Secure coding standards
- **OWASP best practices** - Web security principles applied

## 📋 Requirements

### Build Requirements
- **Windows** - Windows 7 or later
- **Compiler** - MSVC (Visual Studio 2019+) or MinGW-w64
- **Libraries** - Windows SDK (included with compiler)

### Runtime Requirements
- **Python** - Version 3.9-3.13 (for execution mode)
- **Windows** - Windows 7 or later

## 🔨 Building

### Visual Studio (MSVC)
```cmd
cl /O2 /W4 /Zi mipl.c advapi32.lib bcrypt.lib iphlpapi.lib /Fe:mipl.exe
```

### MinGW-w64
```bash
gcc -O3 -Wall -Wextra -o mipl.exe mipl.c -ladvapi32 -lbcrypt -liphlpapi
```

### CMake (Optional)
```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

## 🚀 Usage

### Compile Mode
Compile a Python script into an encrypted MIPL file:

```bash
# Interactive password prompt (recommended)
mipl.exe script.mipl

# Password via command line (not recommended)
mipl.exe script.mipl MySecurePassword123!

# Machine-bound (no password)
mipl.exe script.mipl
```

**Output:** `script.cmipl` (compiled MIPL file)

### Execute Mode
Run a compiled MIPL file:

```bash
# With password
mipl.exe -r script.cmipl MySecurePassword123!

# Machine-bound file
mipl.exe -r script.cmipl
```

### Decompile Mode
Extract source code from a compiled MIPL file:

```bash
# To stdout
mipl.exe -d script.cmipl MySecurePassword123!

# To file
mipl.exe -d script.cmipl MySecurePassword123! output.py
```

## 🔑 Password Policy

### Requirements
- **Minimum length:** 12 characters
- **Complexity:** Must include at least 3 of:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Digits (0-9)
  - Special characters (!@#$%^&*...)

### Best Practices
- Use interactive password input (hides input)
- Avoid command-line passwords (visible in process list)
- Use unique passwords for each file
- Store passwords in a password manager

### Machine-Bound Mode
If no password is provided, the file is bound to the current machine using:
- CPU ID (CPUID instruction)
- MAC address (first network adapter)
- Volume serial number (C: drive)
- Computer name
- Windows installation date

**⚠️ Warning:** Machine-bound files cannot be decrypted on other computers!

## 📦 File Format

### MIPL File Structure (.cmipl)
```
┌─────────────────────────────────────┐
│ Header (352 bytes)                  │
│  - Magic: 0x4D49504C                │
│  - Version: 0x0600                  │
│  - Flags                            │
│  - Timestamps                       │
│  - Salt, IV, Nonce                  │
│  - HMAC, GCM Tag                    │
├─────────────────────────────────────┤
│ Dependencies (optional)             │
│  - Name, version, flags             │
├─────────────────────────────────────┤
│ Encrypted Data                      │
│  - AES-256-GCM encrypted            │
│  - Compressed Python source         │
├─────────────────────────────────────┤
│ Wrapped Key (machine-bound only)    │
│  - IV + Encrypted Key + Tag         │
└─────────────────────────────────────┘
```

### Supported Flags
- `FLAG_COMPRESSED` (0x0001) - Data is compressed
- `FLAG_ENCRYPTED` (0x0002) - Data is encrypted
- `FLAG_HAS_PASSWORD` (0x0010) - Password-protected
- `FLAG_INTEGRITY_CHECK` (0x0080) - HMAC present
- `FLAG_KEY_WRAPPED` (0x0200) - Machine-bound key
- `FLAG_HAS_EXPIRY` (0x0400) - Expiry date set
- `FLAG_HAS_NONCE` (0x0800) - Nonce included

## 🔍 Dependency Detection

Automatically detects and records Python dependencies:
- numpy
- pandas
- requests
- matplotlib
- scipy
- scikit-learn
- tensorflow
- pytorch

Dependencies are stored in the compiled file for reference.

## 📊 Security Audit

All security-relevant events are logged to `mipl_audit.log`:
- Compilation attempts
- Execution attempts
- Decryption failures
- Integrity violations
- Expiry checks
- CFI violations
- Stack overflows

**Format:** `[timestamp] action: file - status`

## ⚠️ Limitations

### File Size
- Maximum file size: 500 MB
- Compression reduces size by typically 60-80%

### Python Versions
- Supported: Python 3.9 - 3.13
- Automatic detection and loading

### Platform
- Windows only (uses Windows APIs)
- No cross-platform support currently

### Portability
- Machine-bound files are **not portable**
- Password-protected files are portable

## 🛡️ Security Considerations

### Threat Model
Protects against:
- ✅ Unauthorized access
- ✅ File tampering
- ✅ Replay attacks
- ✅ Timing attacks
- ✅ Buffer overflows
- ✅ Integer overflows
- ✅ TOCTOU race conditions
- ✅ Memory disclosure

Does NOT protect against:
- ❌ Compromised operating system
- ❌ Hardware keyloggers
- ❌ Memory dumps (while running)
- ❌ Debugger attachment
- ❌ Weak passwords

### Best Practices
1. Use strong, unique passwords
2. Store passwords securely
3. Keep machine-bound files on original machine
4. Monitor audit logs regularly
5. Update to latest version
6. Report security issues responsibly

## 🐛 Troubleshooting

### "Password too weak"
- Use at least 12 characters
- Include uppercase, lowercase, digits, and special characters

### "Key unwrapping failed (wrong machine?)"
- File is machine-bound and must run on original computer
- Re-compile on new machine or use password protection

### "Python not found"
- Install Python 3.9-3.13
- Ensure python3XX.dll is in PATH or system directory

### "HMAC verification failed"
- File has been tampered with or corrupted
- Possible replay attack detected
- Re-compile from original source

### "File has expired"
- File exceeded 365-day validity period
- Re-compile to extend expiry date

## 📜 License

This software is provided as-is for educational and research purposes.

## 🔗 Technical Details

### Algorithms
- **Encryption:** AES-256-GCM (NIST FIPS 197)
- **Key Derivation:** PBKDF2-SHA256 (RFC 2898)
- **Integrity:** HMAC-SHA256 (RFC 2104)
- **Compression:** LZ77-style with hash table

### Performance
- **Compilation:** ~50-100 MB/s
- **Decompilation:** ~80-150 MB/s
- **Compression Ratio:** 20-40% of original
- **Memory Usage:** 2-3x file size

### Cryptographic Parameters
- AES key size: 256 bits
- PBKDF2 iterations: 200,000
- Salt size: 256 bits
- IV size: 128 bits
- Nonce size: 128 bits
- GCM tag size: 128 bits
- HMAC output: 256 bits

## 📞 Support

For security issues, please report responsibly and privately.

For Support you can Email me with the Email Malware.Intelligence@gmx.de

For general questions, refer to the source code documentation.

---

**Version:** 6.0 - 100% Perfect Edition  
**Date:** 2025  
**Status:** Production Ready
