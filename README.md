# Firewall
A Firewall module with data security and network security rules
# Firewall Scanner with GUI Interface

This project is a Python-based Firewall Scanner with a GUI interface designed to enhance both data security and network security. The tool efficiently detects malicious files and suspicious network activity using established malware signatures and patterns.

## Features

### File Scanning
- Identifies malicious files by comparing file hashes against known malware signatures.
- Detects suspicious patterns to identify potential threats.
- Blocks files with potentially harmful extensions to mitigate risks.

### Network Scanning
- Uses ARP scanning to identify active devices on the local network.
- Detects unusual or unauthorized network activity for enhanced security.

### Logging
- All detected threats are logged in organized text files for further analysis and auditing.

## Requirements
- Python 3.x
- `tkinter` for the GUI interface
- `scapy` for network scanning
- `hashlib` for file hash comparison
- `os` and `shutil` for file management

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/GargSaksham/Firewall.git
   ```

## Usage
1. Run the main script:
   ```bash
   python main.py
   ```
2. Use the GUI interface to:
   - Start file scanning by selecting a directory.
   - Perform network scans to identify connected devices.
   - Review logs for detected threats.

## Configuration
- You can modify file extension blocklists and malware signature patterns in the `config.json` file.
- Log files will be stored in the `logs/` directory.

## Contributions
Contributions are welcome! Feel free to submit pull requests or report issues on the repository.

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Contact
For questions, feel free to reach out at [sakshamgarg134@gmail.com](mailto:sakshamgarg134@gmail.com).
