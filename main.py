import argparse
import requests
import logging
import socket
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Inspects HTTP headers of a given URL for security-related information.")
    parser.add_argument("url", help="The URL to inspect (e.g., https://www.example.com)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Set request timeout in seconds (default: 10)")
    return parser

def validate_url(url):
    """
    Validates the given URL.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = requests.utils.urlparse(url)
        return all([result.scheme, result.netloc])  # Check for scheme (http/https) and netloc (domain)
    except:
        return False

def check_http_headers(url, timeout=10):
    """
    Inspects HTTP headers of a given URL and reports on security-related headers.

    Args:
        url (str): The URL to inspect.
        timeout (int): Request timeout in seconds.

    Returns:
        dict: A dictionary containing the header information.  Returns None on error.
    """
    try:
        # Send an HTTP GET request to the specified URL
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        headers = response.headers
        return headers
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def analyze_security_headers(headers):
    """
    Analyzes the provided HTTP headers for security-related information.

    Args:
        headers (dict): A dictionary of HTTP headers.

    Returns:
        dict: A dictionary containing analysis results for security headers.
    """
    security_header_results = {}

    # HSTS (HTTP Strict Transport Security)
    if 'Strict-Transport-Security' in headers:
        security_header_results['HSTS'] = headers['Strict-Transport-Security']
    else:
        security_header_results['HSTS'] = 'Not Present'

    # X-Frame-Options
    if 'X-Frame-Options' in headers:
        security_header_results['X-Frame-Options'] = headers['X-Frame-Options']
    else:
        security_header_results['X-Frame-Options'] = 'Not Present'

    # X-Content-Type-Options
    if 'X-Content-Type-Options' in headers:
        security_header_results['X-Content-Type-Options'] = headers['X-Content-Type-Options']
    else:
        security_header_results['X-Content-Type-Options'] = 'Not Present'

    # Content-Security-Policy
    if 'Content-Security-Policy' in headers:
        security_header_results['Content-Security-Policy'] = headers['Content-Security-Policy']
    else:
        security_header_results['Content-Security-Policy'] = 'Not Present'

    # Referrer-Policy
    if 'Referrer-Policy' in headers:
        security_header_results['Referrer-Policy'] = headers['Referrer-Policy']
    else:
        security_header_results['Referrer-Policy'] = 'Not Present'

    # Permissions-Policy (formerly Feature-Policy)
    if 'Permissions-Policy' in headers:
        security_header_results['Permissions-Policy'] = headers['Permissions-Policy']
    elif 'Feature-Policy' in headers: #For older servers
        security_header_results['Permissions-Policy'] = headers['Feature-Policy']
    else:
        security_header_results['Permissions-Policy'] = 'Not Present'

    return security_header_results

def print_security_header_results(results):
    """
    Prints the security header analysis results to the console.

    Args:
        results (dict): A dictionary containing the security header analysis results.
    """
    print("\n--- Security Header Analysis ---")
    for header, value in results.items():
        print(f"{header}: {value}")

def main():
    """
    Main function to execute the net-header-checker tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    url = args.url

    if not validate_url(url):
        logging.error("Invalid URL.  Please provide a URL including the scheme (http:// or https://).")
        sys.exit(1)

    try:
        headers = check_http_headers(url, args.timeout)

        if headers:
            security_analysis = analyze_security_headers(headers)
            print_security_header_results(security_analysis)
        else:
            logging.error("Failed to retrieve headers.")
            sys.exit(1)
    except socket.timeout:
        logging.error(f"Timeout occurred after {args.timeout} seconds.  The server may be down or slow to respond.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Usage examples:
    # 1. Basic usage: python main.py https://www.example.com
    # 2. Verbose mode: python main.py -v https://www.example.com
    # 3. Custom timeout: python main.py -t 5 https://www.example.com
    main()