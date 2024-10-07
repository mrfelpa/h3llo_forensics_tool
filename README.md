# Key Features

- Automated collection of system information
- Detailed analysis of network configuration
- Real-time visualization of progress using Rich
- Complete logging of all operations
- Export results in JSON format
- Built-in network scanner for active host detection
  
![h3llo](https://github.com/user-attachments/assets/f2078cb5-8604-4920-ad7e-8428d76f0038)

# System Requirements

- Windows 7 or higher
- Python 3.7+
- Administrator privileges for some features

# Use

- Basic Syntax

      python h3llo.py [--subnet SUBNET] [--output OUTPUT_FILE] [--log LOG_FILE]

# Parameters

***--subnet:*** Defines the subnet to scan ***(ex: 192.168.1)***

***--output:*** Sets the output file for the results ***(default: forensic_results.json)***

***--log:*** Sets the log file location ***(default: forensic_scan.log)***

# Usage Example

        python h3llo.py --subnet 192.168.1 --output results/analysis_forense.json

# Output Structure

- The tool generates a JSON file with the following structure: 

          {
              "timestamp": "2024-10-07T10:00:00",
              "system_info": {
                  "Hostname": "...",
                  "System Info": "...",
                  ...
              },
              "network_info": {
                  "Network Shares": "...",
                  "Active Connections": "...",
                  ...
              },
              "active_hosts": [
                  "192.168.1.1",
                  "192.168.1.2",
                  ...
              ]
          }

# Limitations

- Only works on Windows systems
- Some features require elevated privileges
- The network scanner may be affected by firewalls or restrictive network settings

# Disclaimer

- This tool should only be used on systems and networks where you have explicit permission to perform forensic analysis, improper use may violate local laws.
