# Automated Address Blocker for Growtopia Private Server

This script automates the process of blocking malicious requests to a Growtopia Private Server by managing firewall rules. It monitors incoming requests, identifies patterns associated with malicious behavior, and enforces blocks to enhance the server's security.

The script can be customized using command-line arguments to specify the server's host address and port number. It also supports SSL/TLS encryption with provided certificate and key files.

## Features

- Automatically blocks malicious requests to the Growtopia Private Server
- Customizable host address and port settings
- SSL/TLS support with provided certificate and key files

## Usage

To run the script, use the following command in your terminal:

```bash
python script.py -h <host_address> -p <port_number>
```
## Script Limitations

Please keep in mind that while using this script can provide some protection, it does not guarantee immunity from spam requests and potential disruptions.