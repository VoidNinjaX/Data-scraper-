import requests
from bs4 import BeautifulSoup
import socket
import ssl
import re
import concurrent.futures
import os

# Validate the URL format
def validate_url(url):
    if not re.match(r'^https?://', url) and not re.match(r'^file://', url):
        url = 'http://' + url
    return url

# Check for common vulnerabilities
def check_vulnerabilities(url):
    vulnerabilities = []

    if url.startswith('file://'):
        # Handle local file case
        local_path = url.replace('file://', '')
        if os.path.exists(local_path):
            with open(local_path, 'r', encoding='utf-8') as file:
                content = file.read()
                if '<script>' in content:
                    vulnerabilities.append("Possible XSS vulnerability detected in local file")
        else:
            vulnerabilities.append(f"Local file {local_path} does not exist")
        return vulnerabilities
    else:
        # Web URL case
        try:
            response = requests.get(url)
            if '<script>' in response.text:
                vulnerabilities.append("Possible XSS vulnerability detected")
        except requests.RequestException as e:
            vulnerabilities.append(f"Failed to fetch the website content: {e}")
            return vulnerabilities

        # Check for common open ports
        ports = [80, 443, 22, 21, 8080, 3306, 25]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(is_port_open, url, port) for port in ports]
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    vulnerabilities.append(f"Port {port} is open")

        # Check for SSL certificate validity
        if url.startswith('https://'):
            if not is_ssl_valid(url):
                vulnerabilities.append("SSL certificate is invalid or expired")

        # Check for insecure HTTP headers
        headers = response.headers
        if 'X-Content-Type-Options' not in headers:
            vulnerabilities.append("Missing security header: X-Content-Type-Options")
        if 'Strict-Transport-Security' not in headers:
            vulnerabilities.append("Missing security header: Strict-Transport-Security")

    return vulnerabilities

# Check if a specific port is open
def is_port_open(url, port):
    try:
        socket.setdefaulttimeout(1)
        ip = socket.gethostbyname(url.replace('http://', '').replace('https://', ''))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port, result == 0
    except (socket.timeout, socket.error) as e:
        return port, False

# Check if SSL certificate is valid
def is_ssl_valid(url):
    try:
        # Extract the hostname from the URL
        host = url.replace('https://', '').replace('http://', '').split('/')[0]

        if not host:
            raise ValueError(f"Invalid URL: {url}")

        context = ssl.create_default_context()
        with socket.create_connection((host, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # Check if the certificate is valid
                return bool(cert)
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
        return False
    except socket.gaierror as e:
        print(f"Socket error: {e} - Unable to resolve the domain {url}")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

# Detect server information from HTTP headers
def detect_server_info(url):
    if url.startswith('file://'):
        return "Local file, no server information"
    try:
        response = requests.head(url)
        server_info = response.headers.get('Server', 'Unknown')
        return f"Server Information: {server_info}"
    except requests.RequestException:
        return "Failed to retrieve server information"

# Main function
def main():
    url = input("Enter the URL to scan (with http/https or file://): ")
    url = validate_url(url)

    print("Scanning for vulnerabilities...")
    vulnerabilities = check_vulnerabilities(url)

    if vulnerabilities:
        print("\nVulnerabilities found:")
        for vuln in vulnerabilities:
            print(f" - {vuln}")
    else:
        print("\nNo vulnerabilities found")

    # Detect server info
    print("\n" + detect_server_info(url))

if __name__ == '__main__':
    main()
