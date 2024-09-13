CHECK PNG FOR WHAT IT LOOKS LIKE WHEN IT DOES FIND SOMETHING!

# Vulnerability Scanner

This is a Python-based vulnerability scanner that checks for common security issues such as Cross-Site Scripting (XSS), open ports, SSL certificate validity, and missing HTTP security headers. It supports both web URLs (`http://`, `https://`) and local HTML files (`file://`).

## Features

- **XSS Vulnerability Detection**: Scans for the presence of `<script>` tags in the webpage or local file.
- **Port Scanning**: Checks if common ports (e.g., 80, 443, 22, 21, etc.) are open on the target web server.
- **SSL Certificate Check**: Verifies if the SSL certificate is valid or expired (for HTTPS URLs).
- **HTTP Header Security Check**: Looks for important security headers like `X-Content-Type-Options` and `Strict-Transport-Security`.
- **Local File Scanning**: If you provide a local file using a `file://` URL, it checks for XSS vulnerabilities within the file.

## Installation

1. **Clone the repository**:
    
    git clone https://github.com/your-repo/vulnerability-scanner.git
    cd vulnerability-scanner
  

2. **Install the required dependencies**:
   
    pip install -r requirements.txt
   

## Usage

Run the script and input the URL (web or local file):


python main.py


You will be prompted to enter a URL to scan:


Enter the URL to scan (with http/https or file://):


### Example for a Web URL:


Enter the URL to scan (with http/https): https://example.com


### Example for a Local File:


Enter the URL to scan (with http/https or file://): file:///path/to/your/file.html


The tool will scan the given URL and report any detected vulnerabilities.

## Limitations

- **Local File Scanning**: The tool supports scanning local HTML files for XSS vulnerabilities but does not support network-related scans (such as port scanning or SSL checks) for local files.
- **Web URLs Only**: The tool is designed for use with web URLs (`http://`, `https://`). Attempts to scan other URL types, such as `file://`, may produce unexpected results.
- **Port Scanning**: The tool only checks a predefined list of ports (80, 443, 22, 21, 8080, 3306, 25). It does not perform a full port scan.
- **SSL Check**: The SSL certificate validity check only works for HTTPS URLs. If the site uses an unusual SSL setup or does not support standard ports, the tool might fail.
- **Not a Full Security Audit**: This is a basic vulnerability scanner intended for quick checks. It will not catch all security issues, nor is it intended as a substitute for professional security audits.

## Troubleshooting

- If you encounter errors related to socket or DNS resolution, verify that the URL is correctly formatted and the target is accessible.
- The tool may not always work due to network issues, timeouts, or non-standard server configurations.

## Disclaimer

This tool is intended for educational purposes only. It is not a replacement for professional security tools or audits. The author takes no responsibility for the use of this tool on unauthorized systems.

## License

This project is licensed under the MIT License.



