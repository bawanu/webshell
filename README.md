# Stealth Web Shell - Management & Compatible V3

A high-performance, stealth-oriented PHP management interface designed for security auditing and forensic analysis. This system focuses on zero-trace operation, cross-platform compatibility (Windows/Linux), and anti-reverse engineering.

## 🚀 Key Features

### 🛡️ Stealth & Anti-Forensics
- **404 Masking**: The shell defaults to a standard Apache "404 Not Found" page.
- **Secret Reveal**: The login interface is hidden and only revealed using the keyboard shortcut: `Ctrl + Shift + K`.
- **Bot Detection**: Automatically filters and blocks common scanners (Shodan, Censys, Googlebot, etc.).
- **Sandbox Detection**: Detects analysis environments (XDebug, proxy headers) and self-terminates or shows the 404 page.
- **Zero Logging**: Disables PHP error logging and suppresses Apache access logs where possible (`apache_setenv`).
- **RAM-Only Operation**: Payloads are decrypted and executed directly in memory (`eval`) without writing temporary source files to disk.

### 💻 System Information
- **Public IP Tracking**: Retrieves the server's public IP address via external APIs with multiple fallbacks.
- **Domain Identification**: Displays the actual hosted domain name.
- **OS Compatibility**: Fully supports both Windows and Linux, including process management and networking checks.
- **Available Commands**: Real-time status check for system binaries (curl, wget, python, etc.).

### 📂 File Management & Tools
- **Advanced File Manager**: Full CRUD support, permission editing (octal), and file timestamp modification.
- **External Upload**: Download files directly from an external URL to the server's current directory.
- **Database Dump**: Detects MySQL/MariaDB services, allows database selection, and generates SQL dumps for direct download to the client PC.
- **Network Scanner**: Integrated local network host discovery and port scanner.
- **Reverse Shell**: Multi-session reverse shell manager with status monitoring.

## 🛠️ Security & Encryption

The system employs **AES-256-GCM** (Authenticated Encryption with Associated Data) to ensure the payload cannot be tampered with or analyzed without the correct key.

1. **Encrypted Loader (`secure_manager.php`)**: The core logic is encrypted. Access requires the correct vault key.
2. **Obfuscated Standalone (`obfuscated_webshell.php`)**: A specialized version using multi-layer XOR encoding and dynamic function resolution for maximum obfuscation without password protection.

## 📋 Installation & Usage

1. **Deployment**: Upload `secure_manager.php` to your target directory.
2. **Access**: Navigate to the URL with the mandatory "Ghost Key" parameter to bypass the 404 trigger:
   `http://your-server.com/secure_manager.php?PHPSSIDLOGINFODATARECOVESSRYSYSTEM=SYSTEM32LOGFILEINSTANCE`
3. **Login**: Press `Ctrl + Shift + K` to show the password field. The default password is `1234shell`.
4. **Operations**: Use the tabs to navigate between the File Manager, System Info, Processes, and Networking tools.

## ⚠️ Legal Disclaimer
This software is intended for authorized security auditing and educational purposes only. Unauthorized access to computer systems is illegal. The authors assume no liability for any misuse of this tool.
