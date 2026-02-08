# Stealth Web Shell - Management & Compatible V3

A high-performance, stealth-oriented PHP management interface designed for security auditing and forensic analysis. This system focuses on zero-trace operation, cross-platform compatibility (Windows/Linux), and anti-reverse engineering.

## 🚀 Key Features

### 🛡️ Advanced Stealth & Anti-Analysis
- **Dynamic 404 Facade**: Implements a perfect mimic of a standard Apache "404 Not Found" error. The actual management interface remains invisible to unauthorized users and automated crawlers.
- **Secret Reveal Mechanism**: The login form is rendered with `opacity: 0` and is completely non-interactive until triggered by the secret hotkey combination: **`Ctrl + Shift + K`**.
- **Comprehensive Bot Filtering**: Proactively detects and redirects requests from security scanners and crawlers, including Shodan, Censys, Virustotal, and common search engine bots.
- **Sandbox & Analysis Evasion**: Checks for the presence of debugging tools (e.g., XDebug), suspicious proxy headers (`X-Forwarded-For` with loopback IPs, `Via`), and specific server configurations to avoid analysis in controlled environments.
- **Anti-Forensics Logging Suppression**:
  - Disables PHP `error_log` and `display_errors` at runtime.
  - Attempts to suppress Apache access logging using `apache_setenv('dont-log', '1')`.
  - Background processes are self-cleaning (`@unlink(__FILE__)`).
- **RAM-Only Execution**: Core payloads are delivered in an encrypted state and decrypted directly into the PHP execution engine (`eval`) within memory, leaving no unencrypted trace on the disk.

### 💻 System Information & Host Identification
- **Accurate Public IP Resolution**: Uses multiple redundant external APIs (ipify.org, ifconfig.me) to determine the server's true public-facing IP address.
- **Domain & Service Mapping**: Automatically identifies the hosted domain name and maps local database services (MySQL, MariaDB, PostgreSQL, MongoDB, Redis).
- **Cross-Platform Compatibility Engine**: Transparently handles OS differences between Windows and Linux for:
  - Command availability status (green/red indicators).
  - Process listing (`tasklist` vs `ps`).
  - Network state and port detection (`netstat -ano`).
- **Visual Status Dashboard**: Real-time monitoring of available system tools (curl, wget, gcc, python, etc.).

### 📂 Comprehensive Management Tools
- **Advanced File Manager**:
  - Standard CRUD operations (Create, Read, Update, Delete).
  - **Massive File Support**: Handles large uploads and downloads via secure streams.
  - **Metadata Manipulation**: Ability to modify file permissions (octal) and "Touch" files to alter access/modification timestamps.
  - **External URL Ingestion**: A dedicated "Upload from Link" feature allows the server to pull files directly from remote URLs into the current directory.
- **Database Export & Discovery**:
  - Automates the discovery of local MySQL/MariaDB instances.
  - Interactive database selection and credential testing.
  - Generates full SQL dumps (using `mysqldump` with a robust PHP-based fallback) delivered directly to the user's browser as a download.
- **Network Discovery Suite**:
  - **Host Scanner**: ARP/Ping-based discovery for local network ranges (CIDR or Range support).
  - **Port Scanner**: Multi-threaded port scanning for discovered hosts with customizable presets.
- **Reverse Shell Manager**: Supports multiple concurrent reverse shell sessions with interactive control and status tracking.

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
