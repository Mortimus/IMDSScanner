# IMDS Scanner

**IMDS Scanner** is a Red Team utility designed to deeply enumerate and extract information from Cloud Instance Metadata Services (IMDS). 

It is designed for situations where you have Command Injection or Shell access on a cloud instance (or a container/pod within it) and need to rapidly identify the environment, extract credentials, and map the attack surface.

**Author:** Mortimus  
**Repository:** [https://github.com/Mortimus/IMDSScanner](https://github.com/Mortimus/IMDSScanner)

---

## Features

* **Auto-Detection:** Automatically identifies the Cloud Provider (AWS, GCP, Azure, Oracle Cloud) by correlating external IP ASN/ISP data and internal metadata headers.
* **WAF/Filter Evasion:** Automatically tries 7 different obfuscated representations of `169.254.169.254` (Octal, Hex, Dotted Hex, etc.) to bypass string-based regex filters.
* **AWS Recursive Crawling:** Since AWS IMDS does not support a native "dump all" feature, the tool includes a custom spider that walks the directory tree to retrieve all available keys.
* **IMDSv2 Support:** Automatically attempts to negotiate a Session Token for AWS IMDSv2. If successful, it injects the token into all subsequent requests.
* **Full JSON Dumps:** Retrieves the complete JSON configuration for GCP and Azure instances.
* **Interface Binding:** Allows you to force traffic through a specific network interface (e.g., `eth0`, `ens5`) to bypass complex routing tables or Docker bridge networks.
* **Stealth Mode:** Can disable external connectivity checks to remain entirely internal.

## Installation

No installation required. It is a standalone Bash script.

```bash
# Download
wget [https://github.com/Mortimus/IMDSScanner/raw/main/cloud_meta_enum.sh](https://github.com/Mortimus/IMDSScanner/raw/main/cloud_meta_enum.sh)

# Make executable
chmod +x cloud_meta_enum.sh

# Run
./cloud_meta_enum.sh
