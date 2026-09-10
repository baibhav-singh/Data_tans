#!/usr/bin/env python3
"""
Parallel SSL Certificate Downloader
Downloads SSL certificates for all domains in whitelistv6.csv with parallel processing.
"""

import os
import sys
import ssl
import socket
import argparse
import threading
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Thread-safe progress counter
progress_lock = threading.Lock()
progress_data = {
    'current': 0,
    'success': 0,
    'failed': 0,
    'failed_domains': []
}


def download_certificate(domain, output_dir, timeout=10):
    """
    Download SSL certificate for a given domain.

    Args:
        domain: Domain name to download certificate from
        output_dir: Directory to save the certificate
        timeout: Connection timeout in seconds

    Returns:
        tuple: (success: bool, message: str, domain: str)
    """
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Connect to the domain
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get the certificate in DER format
                der_cert = ssock.getpeercert(binary_form=True)

                if not der_cert:
                    return False, "No certificate returned", domain

                # Convert DER to PEM format
                import base64
                pem_cert = b"-----BEGIN CERTIFICATE-----\n"
                pem_cert += base64.b64encode(der_cert)
                pem_cert += b"\n-----END CERTIFICATE-----\n"

                # Save to file
                cert_filename = domain.replace('.', '_') + '.pem'
                cert_path = os.path.join(output_dir, cert_filename)

                with open(cert_path, 'wb') as f:
                    f.write(pem_cert)

                return True, "OK", domain

    except socket.timeout:
        return False, "Timeout", domain
    except socket.gaierror:
        return False, "DNS error", domain
    except ConnectionRefusedError:
        return False, "Connection refused", domain
    except ssl.SSLError as e:
        return False, "SSL error", domain
    except Exception as e:
        error_msg = type(e).__name__
        return False, error_msg, domain


def print_progress_bar(current, total, width=50):
    """Print a progress bar to the console."""
    if total == 0:
        return

    percent = current / total
    filled = int(width * percent)
    bar = '█' * filled + '░' * (width - filled)

    sys.stdout.write(f'\r[{bar}] {current}/{total} ({percent*100:.1f}%)')
    sys.stdout.flush()


def update_progress(success, domain):
    """Thread-safe progress update."""
    global progress_data

    with progress_lock:
        progress_data['current'] += 1

        if success:
            progress_data['success'] += 1
        else:
            progress_data['failed'] += 1
            progress_data['failed_domains'].append(domain)

        # Update progress bar every update
        print_progress_bar(
            progress_data['current'],
            total_domains
        )


def main():
    global total_domains

    parser = argparse.ArgumentParser(
        description='Download SSL certificates for domains in a whitelist file (with parallel processing)'
    )
    parser.add_argument(
        '-w', '--whitelist',
        default='whitelistv6.csv',
        help='Path to whitelist file (default: whitelistv6.csv)'
    )
    parser.add_argument(
        '-o', '--output',
        default='cert_dump',
        help='Output directory for certificates (default: cert_dump)'
    )
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=10,
        help='Connection timeout in seconds (default: 10)'
    )
    parser.add_argument(
        '-p', '--parallel',
        type=int,
        default=20,
        help='Number of parallel workers (default: 20)'
    )

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    output_dir = args.output
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    print(f"Output directory: {output_dir}")
    print(f"Parallel workers: {args.parallel}")
    print(f"Connection timeout: {args.timeout}s\n")

    # Read whitelist file
    if not os.path.isfile(args.whitelist):
        print(f"Error: Whitelist file '{args.whitelist}' not found")
        sys.exit(1)

    # Parse domains from whitelist
    domains = []
    try:
        with open(args.whitelist, 'r') as f:
            for line in f:
                domain = line.strip()
                # Skip empty lines and comments
                if domain and not domain.startswith('#'):
                    # Remove any leading line numbers if present
                    domain = domain.lstrip('0123456789').lstrip()
                    if domain:
                        domains.append(domain)
    except Exception as e:
        print(f"Error reading whitelist: {e}")
        sys.exit(1)

    if not domains:
        print("No domains found in whitelist file")
        sys.exit(1)

    total_domains = len(domains)
    print(f"Found {total_domains} domains to process\n")
    print("Starting parallel certificate download...\n")

    start_time = datetime.now()

    # Use ThreadPoolExecutor for parallel downloads
    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        # Submit all download tasks
        futures = {
            executor.submit(download_certificate, domain, output_dir, args.timeout): domain
            for domain in domains
        }

        # Process completed tasks
        for future in as_completed(futures):
            try:
                success, message, domain = future.result()
                update_progress(success, domain)
            except Exception as e:
                update_progress(False, str(e))

    # Print final newline after progress bar
    print()
    print()

    # Calculate elapsed time
    elapsed = datetime.now() - start_time

    # Print summary
    print("=" * 60)
    print("Download Summary:")
    print("=" * 60)
    print(f"  Total domains:    {total_domains}")
    print(f"  Successful:       {progress_data['success']}")
    print(f"  Failed:           {progress_data['failed']}")
    print(f"  Success rate:     {(progress_data['success']/total_domains*100):.1f}%")
    print(f"  Time elapsed:     {str(elapsed).split('.')[0]}")
    print(f"  Avg time/domain:  {(elapsed.total_seconds()/total_domains):.2f}s")
    print(f"  Output directory: {output_dir}")
    print("=" * 60)

    # Print failed domains if any
    if progress_data['failed_domains']:
        num_failed = len(progress_data['failed_domains'])
        print(f"\nFailed domains ({num_failed}):")
        for domain in progress_data['failed_domains'][:20]:  # Show first 20
            print(f"  • {domain}")
        if num_failed > 20:
            print(f"  ... and {num_failed - 20} more")

    # Print certificates saved
    try:
        cert_count = len([f for f in os.listdir(output_dir) if f.endswith('.pem')])
        print(f"\nCertificates saved: {cert_count}")
    except:
        pass


if __name__ == '__main__':
    main()
