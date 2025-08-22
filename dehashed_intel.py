#!/usr/bin/env python3
"""
DeHashed Domain Intelligence Tool

A comprehensive tool for gathering intelligence on domains using the DeHashed API.
"""

import requests
import hashlib
import json
import csv
import os
import argparse
import sys
from datetime import datetime
from typing import Dict, List, Union, Optional, Any, Tuple


class DeHashedAPI:
    """
    Python client for the DeHashed API.

    This client provides access to DeHashed's data breach search, monitoring,
    and WHOIS lookup capabilities through their REST API.
    """

    def __init__(self, api_key: str, base_url: str = "https://api.dehashed.com/v2"):
        """
        Initialize the DeHashed API client.

        Args:
            api_key: Your DeHashed API key
            base_url: Base URL for the API (defaults to v2 endpoint)
        """
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            "Content-Type": "application/json",
            "DeHashed-Api-Key": self.api_key
        }

    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
        """
        Make a request to the DeHashed API.

        Args:
            method: HTTP method (GET, POST)
            endpoint: API endpoint to call
            data: Request payload for POST requests

        Returns:
            API response as a dictionary

        Raises:
            requests.exceptions.HTTPError: If the API returns an error status code
        """
        url = f"{self.base_url}/{endpoint}"

        if method.upper() == "GET":
            response = requests.get(url, headers=self.headers)
        elif method.upper() == "POST":
            response = requests.post(url, headers=self.headers, json=data)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        # Raise an exception for 4XX and 5XX responses
        response.raise_for_status()

        # Return the JSON response
        return response.json()

    # Search API methods
    def search(self, query: str, page: int = 1, size: int = 100, 
               regex: bool = False, wildcard: bool = False, 
               de_dupe: bool = False) -> Dict:
        """
        Search across the DeHashed database.

        Args:
            query: Search query string
            page: Page number for pagination
            size: Number of results per page (max: 10,000)
            regex: Whether to use regex matching
            wildcard: Whether to use wildcard matching
            de_dupe: Whether to remove duplicate results

        Returns:
            Search results

        Note:
            - Maximum pagination depth is 10,000 (e.g., page:3 and size:5000 would be invalid)
            - Regex and Wildcard cannot both be true simultaneously
        """
        if regex and wildcard:
            raise ValueError("Regex and Wildcard cannot both be true simultaneously")

        data = {
            "query": query,
            "page": page,
            "size": size,
            "regex": regex,
            "wildcard": wildcard,
            "de_dupe": de_dupe
        }

        return self._make_request("POST", "search", data)

    def search_password(self, password: str) -> Dict:
        """
        Search for records associated with a specific password hash.

        Args:
            password: Plain text password to search for

        Returns:
            Search results indicating if the password was found

        Note:
            This method doesn't require credits or a subscription to use.
        """
        sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

        data = {
            "sha256_hashed_password": sha256_hash
        }

        return self._make_request("POST", "search-password", data)

    # WHOIS API methods
    def whois_search(self, domain: str) -> Dict:
        """
        Look up WHOIS information for a domain.

        Args:
            domain: Domain to look up (e.g., example.com)

        Returns:
            WHOIS information
        """
        data = {
            "search_type": "whois",
            "domain": domain
        }

        return self._make_request("POST", "whois/search", data)

    def whois_history(self, domain: str) -> Dict:
        """
        Look up WHOIS History for a domain.

        Args:
            domain: Domain to look up (e.g., example.com)

        Returns:
            WHOIS history information

        Note:
            Search Cost is 25 credits
        """
        data = {
            "search_type": "whois-history",
            "domain": domain
        }

        return self._make_request("POST", "whois/search", data)

    def whois_reverse(self, include: List[str] = None, exclude: List[str] = None, 
                     reverse_type: str = "current") -> Dict:
        """
        Look up WHOIS information based on parameters.

        Args:
            include: Terms you want included in your search (max: 4)
            exclude: Terms you want excluded from your search (max: 4)
            reverse_type: 'current' or 'historic', default: 'current'

        Returns:
            Reverse WHOIS information

        Note:
            Include AND Exclude cannot both be empty, you must at least have one term in one of them.
        """
        if not include and not exclude:
            raise ValueError("Include AND Exclude cannot both be empty")

        if include and len(include) > 4:
            raise ValueError("Maximum 4 include terms allowed")

        if exclude and len(exclude) > 4:
            raise ValueError("Maximum 4 exclude terms allowed")

        if reverse_type not in ['current', 'historic']:
            raise ValueError("Reverse type must be one of: 'current', 'historic'")

        data = {
            "search_type": "reverse-whois",
            "reverse_type": reverse_type
        }

        if include:
            data["include"] = include

        if exclude:
            data["exclude"] = exclude

        return self._make_request("POST", "whois/search", data)

    def whois_reverse_ip(self, ip_address: str) -> Dict:
        """
        Look up WHOIS information for an IP Address.

        Args:
            ip_address: IP Address to look up (e.g., 8.8.8.8)

        Returns:
            WHOIS information for the IP
        """
        data = {
            "search_type": "reverse-ip",
            "domain": ip_address
        }

        return self._make_request("POST", "whois/search", data)

    def whois_reverse_mx(self, mx_address: str) -> Dict:
        """
        Look up WHOIS information for a MX server.

        Args:
            mx_address: MX Address to look up (e.g., mx.google.com)

        Returns:
            WHOIS information for the MX server
        """
        data = {
            "search_type": "reverse-mx",
            "domain": mx_address
        }

        return self._make_request("POST", "whois/search", data)

    def whois_reverse_ns(self, ns_address: str) -> Dict:
        """
        Look up WHOIS information for a NS server.

        Args:
            ns_address: NS Address to look up (e.g., ns.google.com)

        Returns:
            WHOIS information for the NS server
        """
        data = {
            "search_type": "reverse-ns",
            "domain": ns_address
        }

        return self._make_request("POST", "whois/search", data)

    def whois_subdomain_scan(self, domain: str) -> Dict:
        """
        Use WHOIS to find subdomains.

        Args:
            domain: Domain to look up (e.g., google.com)

        Returns:
            Subdomain information
        """
        data = {
            "search_type": "subdomain-scan",
            "domain": domain
        }

        return self._make_request("POST", "whois/search", data)

    def whois_credits(self) -> Dict:
        """
        Check your remaining WHOIS credits.

        Returns:
            Remaining WHOIS credits
        """
        return self._make_request("GET", "whois/credits")


class ConsoleColors:
    """ANSI color codes for console output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_banner():
    """Print a nice banner for the tool."""
    banner = f"""
{ConsoleColors.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   {ConsoleColors.BOLD}DeHashed Domain Intelligence Tool{ConsoleColors.END}{ConsoleColors.CYAN}                       ║
║                                                               ║
║   Gather comprehensive intelligence on domains                ║
║   using the DeHashed API                                      ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{ConsoleColors.END}
"""
    print(banner)


def print_section(title):
    """Print a section title with formatting."""
    print(f"\n{ConsoleColors.BOLD}{ConsoleColors.BLUE}[+] {title}{ConsoleColors.END}")


def print_success(message):
    """Print a success message."""
    print(f"  {ConsoleColors.GREEN}✓ {message}{ConsoleColors.END}")


def print_info(message):
    """Print an informational message."""
    print(f"  {ConsoleColors.CYAN}ℹ {message}{ConsoleColors.END}")


def print_warning(message):
    """Print a warning message."""
    print(f"  {ConsoleColors.WARNING}⚠ {message}{ConsoleColors.END}")


def print_error(message):
    """Print an error message."""
    print(f"  {ConsoleColors.RED}✗ {message}{ConsoleColors.END}")


def domain_intelligence_to_csv(api_client, domain: str, output_dir: str = ".", 
                              options: Dict[str, bool] = None, verbose: bool = True) -> str:
    """
    Gather intelligence about a domain from DeHashed based on specified options.

    Args:
        api_client: Initialized DeHashedAPI client
        domain: Domain to investigate (e.g., example.com)
        output_dir: Directory to save CSV files
        options: Dictionary of search options to enable/disable specific searches
        verbose: Whether to print detailed progress messages

    Returns:
        Path to the directory containing all generated CSV files
    """
    # Default options if none provided
    if options is None:
        options = {
            'search_breaches': True,
            'whois': True,
            'whois_history': False,
            'subdomains': True,
            'extract_emails': True
        }

    # Create a timestamped directory for this domain
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain_dir = os.path.join(output_dir, f"{domain.replace('.', '_')}_{timestamp}")
    os.makedirs(domain_dir, exist_ok=True)

    # Dictionary to track all data collected
    collected_data = {}

    # Track statistics for summary
    stats = {
        'records_found': 0,
        'emails_found': 0,
        'subdomains_found': 0,
        'whois_records': 0,
        'whois_history_records': 0,
        'credits_used': 0
    }

    # 1. Check remaining credits
    try:
        print_section("Checking available WHOIS credits")
        credits = api_client.whois_credits()
        if 'whois_credits' in credits:
            print_success(f"You have {credits['whois_credits']} WHOIS credits available")
        else:
            print_warning("Could not determine available credits")
    except Exception as e:
        print_error(f"Error checking credits: {str(e)}")

    # 2. Search for email addresses and other data associated with the domain
    if options.get('search_breaches', True):
        try:
            print_section(f"Searching for data associated with domain: {domain}")
            search_results = api_client.search(f"domain:{domain}", size=1000, de_dupe=True)

            # Track credit usage
            stats['credits_used'] += 1

            if 'entries' in search_results:
                collected_data['domain_search'] = search_results.get('entries', [])
                stats['records_found'] = len(collected_data['domain_search'])

                # Save domain search results to CSV
                if collected_data['domain_search']:
                    output_file = os.path.join(domain_dir, "domain_search_results.csv")
                    _save_entries_to_csv(collected_data['domain_search'], output_file)
                    print_success(f"Found {stats['records_found']} records associated with {domain}")
                    print_info(f"Saved to: {os.path.basename(output_file)}")
                else:
                    print_warning(f"No records found for domain: {domain}")
            else:
                print_warning("Search returned an unexpected response format")
        except Exception as e:
            print_error(f"Error searching domain data: {str(e)}")

    # 3. Get WHOIS information
    if options.get('whois', True):
        try:
            print_section(f"Getting WHOIS information for: {domain}")
            whois_info = api_client.whois_search(domain)

            # Track credit usage
            stats['credits_used'] += 1

            collected_data['whois'] = whois_info

            # Count WHOIS records
            if isinstance(whois_info, dict):
                stats['whois_records'] = 1

                # Save WHOIS data to CSV
                output_file = os.path.join(domain_dir, "whois_info.csv")
                _save_whois_to_csv(whois_info, output_file)
                print_success(f"WHOIS information retrieved for {domain}")
                print_info(f"Saved to: {os.path.basename(output_file)}")

                # Extract and display key WHOIS details
                if verbose:
                    _print_key_whois_details(whois_info)
            else:
                print_warning(f"No WHOIS information found for: {domain}")
        except Exception as e:
            print_error(f"Error retrieving WHOIS data: {str(e)}")

    # 4. Get WHOIS history
    if options.get('whois_history', False):
        try:
            print_section(f"Getting WHOIS history for: {domain}")
            print_info("Note: This operation costs 25 credits")

            whois_history = api_client.whois_history(domain)

            # Track credit usage
            stats['credits_used'] += 25

            collected_data['whois_history'] = whois_history

            # Count WHOIS history records
            if isinstance(whois_history, dict) and 'records' in whois_history:
                stats['whois_history_records'] = len(whois_history['records'])

                # Save WHOIS history to CSV
                output_file = os.path.join(domain_dir, "whois_history.csv")
                _save_whois_history_to_csv(whois_history, output_file)
                print_success(f"Found {stats['whois_history_records']} historical WHOIS records")
                print_info(f"Saved to: {os.path.basename(output_file)}")
            else:
                print_warning(f"No WHOIS history found for: {domain}")
        except Exception as e:
            print_error(f"Error retrieving WHOIS history: {str(e)}")

    # 5. Get subdomains
    if options.get('subdomains', True):
        try:
            print_section(f"Scanning for subdomains of: {domain}")
            subdomains = api_client.whois_subdomain_scan(domain)

            # Track credit usage
            stats['credits_used'] += 1

            collected_data['subdomains'] = subdomains

            # Count subdomains
            if isinstance(subdomains, dict) and 'domains' in subdomains:
                stats['subdomains_found'] = len(subdomains['domains'])

                # Save subdomains to CSV
                output_file = os.path.join(domain_dir, "subdomains.csv")
                _save_subdomains_to_csv(subdomains, output_file)
                print_success(f"Found {stats['subdomains_found']} subdomains")
                print_info(f"Saved to: {os.path.basename(output_file)}")

                # Display some subdomains if verbose
                if verbose and subdomains['domains']:
                    print_info("Sample subdomains:")
                    for i, domain_info in enumerate(subdomains['domains'][:5]):
                        print(f"    - {domain_info.get('domain', 'N/A')}")
                    if len(subdomains['domains']) > 5:
                        print(f"    - ... and {len(subdomains['domains']) - 5} more")
            else:
                print_warning(f"No subdomains found for: {domain}")
        except Exception as e:
            print_error(f"Error scanning for subdomains: {str(e)}")

    # 6. Extract email addresses from search results
    if options.get('extract_emails', True) and 'domain_search' in collected_data:
        try:
            emails = _extract_emails_from_results(collected_data['domain_search'])
            stats['emails_found'] = len(emails)

            if emails:
                output_file = os.path.join(domain_dir, "extracted_emails.csv")
                _save_list_to_csv(emails, ['email'], output_file)
                print_section(f"Email extraction complete")
                print_success(f"Extracted {len(emails)} unique email addresses")
                print_info(f"Saved to: {os.path.basename(output_file)}")

                # Display some emails if verbose
                if verbose and emails:
                    print_info("Sample email addresses:")
                    for i, email in enumerate(emails[:5]):
                        print(f"    - {email}")
                    if len(emails) > 5:
                        print(f"    - ... and {len(emails) - 5} more")
        except Exception as e:
            print_error(f"Error extracting emails: {str(e)}")

    # 7. Create a summary file
    try:
        summary_path = os.path.join(domain_dir, "summary.txt")
        with open(summary_path, 'w') as f:
            f.write(f"DeHashed Intelligence Report for {domain}\n")
            f.write(f"===============================================\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write(f"SUMMARY STATISTICS\n")
            f.write(f"------------------\n")
            if options.get('search_breaches', True):
                f.write(f"Data breach records found: {stats['records_found']}\n")
            if options.get('extract_emails', True):
                f.write(f"Unique email addresses: {stats['emails_found']}\n")
            if options.get('subdomains', True):
                f.write(f"Subdomains discovered: {stats['subdomains_found']}\n")
            if options.get('whois', True):
                f.write(f"WHOIS records: {stats['whois_records']}\n")
            if options.get('whois_history', False):
                f.write(f"Historical WHOIS records: {stats['whois_history_records']}\n")
            f.write(f"Credits used: {stats['credits_used']}\n\n")

            f.write(f"FILES GENERATED\n")
            f.write(f"--------------\n")
            for filename in sorted(os.listdir(domain_dir)):
                if filename != "summary.txt":
                    file_path = os.path.join(domain_dir, filename)
                    file_size = os.path.getsize(file_path)
                    f.write(f"- {filename} ({_format_file_size(file_size)})\n")

            # Add WHOIS summary if available
            if options.get('whois', True) and 'whois' in collected_data and isinstance(collected_data['whois'], dict):
                f.write(f"\nWHOIS SUMMARY\n")
                f.write(f"------------\n")
                whois_data = collected_data['whois']

                # Extract and write key WHOIS details
                if 'domain_name' in whois_data:
                    f.write(f"Domain: {whois_data.get('domain_name', 'N/A')}\n")
                if 'registrar' in whois_data:
                    f.write(f"Registrar: {whois_data.get('registrar', 'N/A')}\n")
                if 'creation_date' in whois_data:
                    f.write(f"Created: {whois_data.get('creation_date', 'N/A')}\n")
                if 'expiration_date' in whois_data:
                    f.write(f"Expires: {whois_data.get('expiration_date', 'N/A')}\n")
                if 'updated_date' in whois_data:
                    f.write(f"Updated: {whois_data.get('updated_date', 'N/A')}\n")
                if 'name_servers' in whois_data:
                    ns = whois_data.get('name_servers', [])
                    if isinstance(ns, list):
                        f.write(f"Name Servers:\n")
                        for server in ns:
                            f.write(f"- {server}\n")
                    else:
                        f.write(f"Name Servers: {ns}\n")

        print_section("Intelligence gathering complete")
        print_success(f"Results saved to: {domain_dir}")
        print_info(f"Summary file: {os.path.basename(summary_path)}")
        print_info(f"Total credits used: {stats['credits_used']}")
    except Exception as e:
        print_error(f"Error creating summary: {str(e)}")

    return domain_dir


def perform_reverse_whois(api_client, include_terms: List[str], exclude_terms: List[str] = None, 
                         reverse_type: str = "current", output_dir: str = ".", verbose: bool = True) -> str:
    """
    Perform a reverse WHOIS lookup.

    Args:
        api_client: Initialized DeHashedAPI client
        include_terms: Terms to include in the search
        exclude_terms: Terms to exclude from the search
        reverse_type: Type of reverse lookup ('current' or 'historic')
        output_dir: Directory to save CSV files
        verbose: Whether to print detailed progress messages

    Returns:
        Path to the output file
    """
    try:
        print_section(f"Performing reverse WHOIS lookup")
        print_info(f"Include terms: {', '.join(include_terms)}")
        if exclude_terms:
            print_info(f"Exclude terms: {', '.join(exclude_terms)}")
        print_info(f"Type: {reverse_type}")

        results = api_client.whois_reverse(include_terms, exclude_terms, reverse_type)

        # Create output filename based on search terms
        terms_str = '_'.join(include_terms).replace(' ', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_dir, f"reverse_whois_{terms_str}_{timestamp}.csv")

        # Save results
        if 'domains' in results and results['domains']:
            domains = results['domains']

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Domain', 'Registrar', 'Created', 'Updated', 'Expires'])

                for domain in domains:
                    writer.writerow([
                        domain.get('domain_name', ''),
                        domain.get('registrar', ''),
                        domain.get('creation_date', ''),
                        domain.get('updated_date', ''),
                        domain.get('expiration_date', '')
                    ])

            print_success(f"Found {len(domains)} domains")
            print_info(f"Results saved to: {os.path.basename(output_file)}")

            # Display sample results if verbose
            if verbose and domains:
                print_info("Sample domains:")
                for i, domain in enumerate(domains[:5]):
                    print(f"    - {domain.get('domain_name', 'N/A')}")
                if len(domains) > 5:
                    print(f"    - ... and {len(domains) - 5} more")
        else:
            print_warning("No domains found matching the criteria")
            # Create empty file
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Domain', 'Registrar', 'Created', 'Updated', 'Expires'])

        return output_file

    except Exception as e:
        print_error(f"Error performing reverse WHOIS lookup: {str(e)}")
        return None


def perform_reverse_lookup(api_client, lookup_type: str, value: str, output_dir: str = ".", verbose: bool = True) -> str:
    """
    Perform a reverse lookup (IP, MX, NS).

    Args:
        api_client: Initialized DeHashedAPI client
        lookup_type: Type of lookup ('ip', 'mx', 'ns')
        value: Value to look up
        output_dir: Directory to save CSV files
        verbose: Whether to print detailed progress messages

    Returns:
        Path to the output file
    """
    try:
        lookup_name = {
            'ip': 'IP address',
            'mx': 'MX server',
            'ns': 'NS server'
        }.get(lookup_type, lookup_type)

        print_section(f"Performing reverse {lookup_name} lookup for: {value}")

        # Call appropriate API method
        if lookup_type == 'ip':
            results = api_client.whois_reverse_ip(value)
        elif lookup_type == 'mx':
            results = api_client.whois_reverse_mx(value)
        elif lookup_type == 'ns':
            results = api_client.whois_reverse_ns(value)
        else:
            raise ValueError(f"Unsupported lookup type: {lookup_type}")

        # Create output filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_value = value.replace('.', '_').replace(':', '_')
        output_file = os.path.join(output_dir, f"reverse_{lookup_type}_{safe_value}_{timestamp}.csv")

        # Save results
        if 'domains' in results and results['domains']:
            domains = results['domains']

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Domain', 'Registrar', 'Created', 'Updated', 'Expires'])

                for domain in domains:
                    writer.writerow([
                        domain.get('domain_name', ''),
                        domain.get('registrar', ''),
                        domain.get('creation_date', ''),
                        domain.get('updated_date', ''),
                        domain.get('expiration_date', '')
                    ])

            print_success(f"Found {len(domains)} domains using this {lookup_name}")
            print_info(f"Results saved to: {os.path.basename(output_file)}")

            # Display sample results if verbose
            if verbose and domains:
                print_info("Sample domains:")
                for i, domain in enumerate(domains[:5]):
                    print(f"    - {domain.get('domain_name', 'N/A')}")
                if len(domains) > 5:
                    print(f"    - ... and {len(domains) - 5} more")
        else:
            print_warning(f"No domains found using this {lookup_name}")
            # Create empty file
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Domain', 'Registrar', 'Created', 'Updated', 'Expires'])

        return output_file

    except Exception as e:
        print_error(f"Error performing reverse {lookup_type} lookup: {str(e)}")
        return None


def _save_entries_to_csv(entries: List[Dict], output_path: str) -> None:
    """Save search result entries to a CSV file with improved formatting."""
    if not entries:
        return

    # Determine all possible fields from all entries
    all_fields = set()
    for entry in entries:
        all_fields.update(entry.keys())

    # Remove 'raw_record' if present as it's typically a nested structure
    if 'raw_record' in all_fields:
        all_fields.remove('raw_record')

    # Prioritize important fields first, then add the rest alphabetically
    priority_fields = ['id', 'email', 'username', 'password', 'hashed_password', 
                      'name', 'address', 'phone', 'ip_address', 'database_name']

    # Create ordered fieldnames list
    fieldnames = []
    for field in priority_fields:
        if field in all_fields:
            fieldnames.append(field)
            all_fields.remove(field)

    # Add remaining fields alphabetically
    fieldnames.extend(sorted(list(all_fields)))

    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for entry in entries:
            # Handle list fields by joining them with commas
            row_data = {}
            for field in fieldnames:
                if field in entry:
                    if isinstance(entry[field], list):
                        row_data[field] = ', '.join(str(item) for item in entry[field])

#!/usr/bin/env python3
"""
DeHashed Domain Intelligence Tool

A comprehensive tool for gathering intelligence on domains using the DeHashed API.
"""

import requests
import hashlib
import json
import csv
import os
import argparse
import sys
from datetime import datetime
from typing import Dict, List, Union, Optional, Any, Tuple


class DeHashedAPI:
    """
    Python client for the DeHashed API.

    This client provides access to DeHashed's data breach search, monitoring,
    and WHOIS lookup capabilities through their REST API.
    """

    def __init__(self, api_key: str, base_url: str = "https://api.dehashed.com/v2"):
        """
        Initialize the DeHashed API client.

        Args:
            api_key: Your DeHashed API key
            base_url: Base URL for the API (defaults to v2 endpoint)
        """
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            "Content-Type": "application/json",
            "DeHashed-Api-Key": self.api_key
        }

    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict:
        """
        Make a request to the DeHashed API.

        Args:
            method: HTTP method (GET, POST)
            endpoint: API endpoint to call
            data: Request payload for POST requests

        Returns:
            API response as a dictionary

        Raises:
            requests.exceptions.HTTPError: If the API returns an error status code
        """
        url = f"{self.base_url}/{endpoint}"

        if method.upper() == "GET":
            response = requests.get(url, headers=self.headers)
        elif method.upper() == "POST":
            response = requests.post(url, headers=self.headers, json=data)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        # Raise an exception for 4XX and 5XX responses
        response.raise_for_status()

        # Return the JSON response
        return response.json()

    # Search API methods
    def search(self, query: str, page: int = 1, size: int = 100, 
               regex: bool = False, wildcard: bool = False, 
               de_dupe: bool = False) -> Dict:
        """
        Search across the DeHashed database.

        Args:
            query: Search query string
            page: Page number for pagination
            size: Number of results per page (max: 10,000)
            regex: Whether to use regex matching
            wildcard: Whether to use wildcard matching
            de_dupe: Whether to remove duplicate results

        Returns:
            Search results

        Note:
            - Maximum pagination depth is 10,000 (e.g., page:3 and size:5000 would be invalid)
            - Regex and Wildcard cannot both be true simultaneously
        """
        if regex and wildcard:
            raise ValueError("Regex and Wildcard cannot both be true simultaneously")

        data = {
            "query": query,
            "page": page,
            "size": size,
            "regex": regex,
            "wildcard": wildcard,
            "de_dupe": de_dupe
        }

        return self._make_request("POST", "search", data)

    def search_password(self, password: str) -> Dict:
        """
        Search for records associated with a specific password hash.

        Args:
            password: Plain text password to search for

        Returns:
            Search results indicating if the password was found

        Note:
            This method doesn't require credits or a subscription to use.
        """
        sha256_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

        data = {
            "sha256_hashed_password": sha256_hash
        }

        return self._make_request("POST", "search-password", data)

    # WHOIS API methods
    def whois_search(self, domain: str) -> Dict:
        """
        Look up WHOIS information for a domain.

        Args:
            domain: Domain to look up (e.g., example.com)

        Returns:
            WHOIS information
        """
        data = {
            "search_type": "whois",
            "domain": domain
        }

        return self._make_request("POST", "whois/search", data)

    def whois_history(self, domain: str) -> Dict:
        """
        Look up WHOIS History for a domain.

        Args:
            domain: Domain to look up (e.g., example.com)

        Returns:
            WHOIS history information

        Note:
            Search Cost is 25 credits
        """
        data = {
            "search_type": "whois-history",
            "domain": domain
        }

        return self._make_request("POST", "whois/search", data)

    def whois_reverse(self, include: List[str] = None, exclude: List[str] = None, 
                     reverse_type: str = "current") -> Dict:
        """
        Look up WHOIS information based on parameters.

        Args:
            include: Terms you want included in your search (max: 4)
            exclude: Terms you want excluded from your search (max: 4)
            reverse_type: 'current' or 'historic', default: 'current'

        Returns:
            Reverse WHOIS information

        Note:
            Include AND Exclude cannot both be empty, you must at least have one term in one of them.
        """
        if not include and not exclude:
            raise ValueError("Include AND Exclude cannot both be empty")

        if include and len(include) > 4:
            raise ValueError("Maximum 4 include terms allowed")

        if exclude and len(exclude) > 4:
            raise ValueError("Maximum 4 exclude terms allowed")

        if reverse_type not in ['current', 'historic']:
            raise ValueError("Reverse type must be one of: 'current', 'historic'")

        data = {
            "search_type": "reverse-whois",
            "reverse_type": reverse_type
        }

        if include:
            data["include"] = include

        if exclude:
            data["exclude"] = exclude

        return self._make_request("POST", "whois/search", data)

    def whois_reverse_ip(self, ip_address: str) -> Dict:
        """
        Look up WHOIS information for an IP Address.

        Args:
            ip_address: IP Address to look up (e.g., 8.8.8.8)

        Returns:
            WHOIS information for the IP
        """
        data = {
            "search_type": "reverse-ip",
            "domain": ip_address
        }

        return self._make_request("POST", "whois/search", data)

    def whois_reverse_mx(self, mx_address: str) -> Dict:
        """
        Look up WHOIS information for a MX server.

        Args:
            mx_address: MX Address to look up (e.g., mx.google.com)

        Returns:
            WHOIS information for the MX server
        """
        data = {
            "search_type": "reverse-mx",
            "domain": mx_address
        }

        return self._make_request("POST", "whois/search", data)

    def whois_reverse_ns(self, ns_address: str) -> Dict:
        """
        Look up WHOIS information for a NS server.

        Args:
            ns_address: NS Address to look up (e.g., ns.google.com)

        Returns:
            WHOIS information for the NS server
        """
        data = {
            "search_type": "reverse-ns",
            "domain": ns_address
        }

        return self._make_request("POST", "whois/search", data)

    def whois_subdomain_scan(self, domain: str) -> Dict:
        """
        Use WHOIS to find subdomains.

        Args:
            domain: Domain to look up (e.g., google.com)

        Returns:
            Subdomain information
        """
        data = {
            "search_type": "subdomain-scan",
            "domain": domain
        }

        return self._make_request("POST", "whois/search", data)

    def whois_credits(self) -> Dict:
        """
        Check your remaining WHOIS credits.

        Returns:
            Remaining WHOIS credits
        """
        return self._make_request("GET", "whois/credits")


class ConsoleColors:
    """ANSI color codes for console output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_banner():
    """Print a nice banner for the tool."""
    banner = f"""
{ConsoleColors.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   {ConsoleColors.BOLD}DeHashed Domain Intelligence Tool{ConsoleColors.END}{ConsoleColors.CYAN}                       ║
║                                                               ║
║   Gather comprehensive intelligence on domains                ║
║   using the DeHashed API                                      ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{ConsoleColors.END}
"""
    print(banner)


def print_section(title):
    """Print a section title with formatting."""
    print(f"\n{ConsoleColors.BOLD}{ConsoleColors.BLUE}[+] {title}{ConsoleColors.END}")


def print_success(message):
    """Print a success message."""
    print(f"  {ConsoleColors.GREEN}✓ {message}{ConsoleColors.END}")


def print_info(message):
    """Print an informational message."""
    print(f"  {ConsoleColors.CYAN}ℹ {message}{ConsoleColors.END}")


def print_warning(message):
    """Print a warning message."""
    print(f"  {ConsoleColors.WARNING}⚠ {message}{ConsoleColors.END}")


def print_error(message):
    """Print an error message."""
    print(f"  {ConsoleColors.RED}✗ {message}{ConsoleColors.END}")


def domain_intelligence_to_csv(api_client, domain: str, output_dir: str = ".", 
                              options: Dict[str, bool] = None, verbose: bool = True) -> str:
    """
    Gather intelligence about a domain from DeHashed based on specified options.

    Args:
        api_client: Initialized DeHashedAPI client
        domain: Domain to investigate (e.g., example.com)
        output_dir: Directory to save CSV files
        options: Dictionary of search options to enable/disable specific searches
        verbose: Whether to print detailed progress messages

    Returns:
        Path to the directory containing all generated CSV files
    """
    # Default options if none provided
    if options is None:
        options = {
            'search_breaches': True,
            'whois': True,
            'whois_history': False,
            'subdomains': True,
            'extract_emails': True
        }

    # Create a timestamped directory for this domain
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain_dir = os.path.join(output_dir, f"{domain.replace('.', '_')}_{timestamp}")
    os.makedirs(domain_dir, exist_ok=True)

    # Dictionary to track all data collected
    collected_data = {}

    # Track statistics for summary
    stats = {
        'records_found': 0,
        'emails_found': 0,
        'subdomains_found': 0,
        'whois_records': 0,
        'whois_history_records': 0,
        'credits_used': 0
    }

    # 1. Check remaining credits
    try:
        print_section("Checking available WHOIS credits")
        credits = api_client.whois_credits()
        if 'whois_credits' in credits:
            print_success(f"You have {credits['whois_credits']} WHOIS credits available")
        else:
            print_warning("Could not determine available credits")
    except Exception as e:
        print_error(f"Error checking credits: {str(e)}")

    # 2. Search for email addresses and other data associated with the domain
    if options.get('search_breaches', True):
        try:
            print_section(f"Searching for data associated with domain: {domain}")
            search_results = api_client.search(f"domain:{domain}", size=1000, de_dupe=True)

            # Track credit usage
            stats['credits_used'] += 1

            if 'entries' in search_results:
                collected_data['domain_search'] = search_results.get('entries', [])
                stats['records_found'] = len(collected_data['domain_search'])

                # Save domain search results to CSV
                if collected_data['domain_search']:
                    output_file = os.path.join(domain_dir, "domain_search_results.csv")
                    _save_entries_to_csv(collected_data['domain_search'], output_file)
                    print_success(f"Found {stats['records_found']} records associated with {domain}")
                    print_info(f"Saved to: {os.path.basename(output_file)}")
                else:
                    print_warning(f"No records found for domain: {domain}")
            else:
                print_warning("Search returned an unexpected response format")
        except Exception as e:
            print_error(f"Error searching domain data: {str(e)}")

    # 3. Get WHOIS information
    if options.get('whois', True):
        try:
            print_section(f"Getting WHOIS information for: {domain}")
            whois_info = api_client.whois_search(domain)

            # Track credit usage
            stats['credits_used'] += 1

            collected_data['whois'] = whois_info

            # Count WHOIS records
            if isinstance(whois_info, dict):
                stats['whois_records'] = 1

                # Save WHOIS data to CSV
                output_file = os.path.join(domain_dir, "whois_info.csv")
                _save_whois_to_csv(whois_info, output_file)
                print_success(f"WHOIS information retrieved for {domain}")
                print_info(f"Saved to: {os.path.basename(output_file)}")

                # Extract and display key WHOIS details
                if verbose:
                    _print_key_whois_details(whois_info)
            else:
                print_warning(f"No WHOIS information found for: {domain}")
        except Exception as e:
            print_error(f"Error retrieving WHOIS data: {str(e)}")

    # 4. Get WHOIS history
    if options.get('whois_history', False):
        try:
            print_section(f"Getting WHOIS history for: {domain}")
            print_info("Note: This operation costs 25 credits")

            whois_history = api_client.whois_history(domain)

            # Track credit usage
            stats['credits_used'] += 25

            collected_data['whois_history'] = whois_history

            # Count WHOIS history records
            if isinstance(whois_history, dict) and 'records' in whois_history:
                stats['whois_history_records'] = len(whois_history['records'])

                # Save WHOIS history to CSV
                output_file = os.path.join(domain_dir, "whois_history.csv")
                _save_whois_history_to_csv(whois_history, output_file)
                print_success(f"Found {stats['whois_history_records']} historical WHOIS records")
                print_info(f"Saved to: {os.path.basename(output_file)}")
            else:
                print_warning(f"No WHOIS history found for: {domain}")
        except Exception as e:
            print_error(f"Error retrieving WHOIS history: {str(e)}")

    # 5. Get subdomains
    if options.get('subdomains', True):
        try:
            print_section(f"Scanning for subdomains of: {domain}")
            subdomains = api_client.whois_subdomain_scan(domain)

            # Track credit usage
            stats['credits_used'] += 1

            collected_data['subdomains'] = subdomains

            # Count subdomains
            if isinstance(subdomains, dict) and 'domains' in subdomains:
                stats['subdomains_found'] = len(subdomains['domains'])

                # Save subdomains to CSV
                output_file = os.path.join(domain_dir, "subdomains.csv")
                _save_subdomains_to_csv(subdomains, output_file)
                print_success(f"Found {stats['subdomains_found']} subdomains")
                print_info(f"Saved to: {os.path.basename(output_file)}")

                # Display some subdomains if verbose
                if verbose and subdomains['domains']:
                    print_info("Sample subdomains:")
                    for i, domain_info in enumerate(subdomains['domains'][:5]):
                        print(f"    - {domain_info.get('domain', 'N/A')}")
                    if len(subdomains['domains']) > 5:
                        print(f"    - ... and {len(subdomains['domains']) - 5} more")
            else:
                print_warning(f"No subdomains found for: {domain}")
        except Exception as e:
            print_error(f"Error scanning for subdomains: {str(e)}")

    # 6. Extract email addresses from search results
    if options.get('extract_emails', True) and 'domain_search' in collected_data:
        try:
            emails = _extract_emails_from_results(collected_data['domain_search'])
            stats['emails_found'] = len(emails)

            if emails:
                output_file = os.path.join(domain_dir, "extracted_emails.csv")
                _save_list_to_csv(emails, ['email'], output_file)
                print_section(f"Email extraction complete")
                print_success(f"Extracted {len(emails)} unique email addresses")
                print_info(f"Saved to: {os.path.basename(output_file)}")

                # Display some emails if verbose
                if verbose and emails:
                    print_info("Sample email addresses:")
                    for i, email in enumerate(emails[:5]):
                        print(f"    - {email}")
                    if len(emails) > 5:
                        print(f"    - ... and {len(emails) - 5} more")
        except Exception as e:
            print_error(f"Error extracting emails: {str(e)}")

    # 7. Create a summary file
    try:
        summary_path = os.path.join(domain_dir, "summary.txt")
        with open(summary_path, 'w') as f:
            f.write(f"DeHashed Intelligence Report for {domain}\n")
            f.write(f"===============================================\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write(f"SUMMARY STATISTICS\n")
            f.write(f"------------------\n")
            if options.get('search_breaches', True):
                f.write(f"Data breach records found: {stats['records_found']}\n")
            if options.get('extract_emails', True):
                f.write(f"Unique email addresses: {stats['emails_found']}\n")
            if options.get('subdomains', True):
                f.write(f"Subdomains discovered: {stats['subdomains_found']}\n")
            if options.get('whois', True):
                f.write(f"WHOIS records: {stats['whois_records']}\n")
            if options.get('whois_history', False):
                f.write(f"Historical WHOIS records: {stats['whois_history_records']}\n")
            f.write(f"Credits used: {stats['credits_used']}\n\n")

            f.write(f"FILES GENERATED\n")
            f.write(f"--------------\n")
            for filename in sorted(os.listdir(domain_dir)):
                if filename != "summary.txt":
                    file_path = os.path.join(domain_dir, filename)
                    file_size = os.path.getsize(file_path)
                    f.write(f"- {filename} ({_format_file_size(file_size)})\n")

            # Add WHOIS summary if available
            if options.get('whois', True) and 'whois' in collected_data and isinstance(collected_data['whois'], dict):
                f.write(f"\nWHOIS SUMMARY\n")
                f.write(f"------------\n")
                whois_data = collected_data['whois']

                # Extract and write key WHOIS details
                if 'domain_name' in whois_data:
                    f.write(f"Domain: {whois_data.get('domain_name', 'N/A')}\n")
                if 'registrar' in whois_data:
                    f.write(f"Registrar: {whois_data.get('registrar', 'N/A')}\n")
                if 'creation_date' in whois_data:
                    f.write(f"Created: {whois_data.get('creation_date', 'N/A')}\n")
                if 'expiration_date' in whois_data:
                    f.write(f"Expires: {whois_data.get('expiration_date', 'N/A')}\n")
                if 'updated_date' in whois_data:
                    f.write(f"Updated: {whois_data.get('updated_date', 'N/A')}\n")
                if 'name_servers' in whois_data:
                    ns = whois_data.get('name_servers', [])
                    if isinstance(ns, list):
                        f.write(f"Name Servers:\n")
                        for server in ns:
                            f.write(f"- {server}\n")
                    else:
                        f.write(f"Name Servers: {ns}\n")

        print_section("Intelligence gathering complete")
        print_success(f"Results saved to: {domain_dir}")
        print_info(f"Summary file: {os.path.basename(summary_path)}")
        print_info(f"Total credits used: {stats['credits_used']}")
    except Exception as e:
        print_error(f"Error creating summary: {str(e)}")

    return domain_dir


def perform_reverse_whois(api_client, include_terms: List[str], exclude_terms: List[str] = None, 
                         reverse_type: str = "current", output_dir: str = ".", verbose: bool = True) -> str:
    """
    Perform a reverse WHOIS lookup.

    Args:
        api_client: Initialized DeHashedAPI client
        include_terms: Terms to include in the search
        exclude_terms: Terms to exclude from the search
        reverse_type: Type of reverse lookup ('current' or 'historic')
        output_dir: Directory to save CSV files
        verbose: Whether to print detailed progress messages

    Returns:
        Path to the output file
    """
    try:
        print_section(f"Performing reverse WHOIS lookup")
        print_info(f"Include terms: {', '.join(include_terms)}")
        if exclude_terms:
            print_info(f"Exclude terms: {', '.join(exclude_terms)}")
        print_info(f"Type: {reverse_type}")

        results = api_client.whois_reverse(include_terms, exclude_terms, reverse_type)

        # Create output filename based on search terms
        terms_str = '_'.join(include_terms).replace(' ', '_')
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_dir, f"reverse_whois_{terms_str}_{timestamp}.csv")

        # Save results
        if 'domains' in results and results['domains']:
            domains = results['domains']

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Domain', 'Registrar', 'Created', 'Updated', 'Expires'])

                for domain in domains:
                    writer.writerow([
                        domain.get('domain_name', ''),
                        domain.get('registrar', ''),
                        domain.get('creation_date', ''),
                        domain.get('updated_date', ''),
                        domain.get('expiration_date', '')
                    ])

            print_success(f"Found {len(domains)} domains")
            print_info(f"Results saved to: {os.path.basename(output_file)}")

            # Display sample results if verbose
            if verbose and domains:
                print_info("Sample domains:")
                for i, domain in enumerate(domains[:5]):
                    print(f"    - {domain.get('domain_name', 'N/A')}")
                if len(domains) > 5:
                    print(f"    - ... and {len(domains) - 5} more")
        else:
            print_warning("No domains found matching the criteria")
            # Create empty file
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Domain', 'Registrar', 'Created', 'Updated', 'Expires'])

        return output_file

    except Exception as e:
        print_error(f"Error performing reverse WHOIS lookup: {str(e)}")
        return None


def perform_reverse_lookup(api_client, lookup_type: str, value: str, output_dir: str = ".", verbose: bool = True) -> str:
    """
    Perform a reverse lookup (IP, MX, NS).

    Args:
        api_client: Initialized DeHashedAPI client
        lookup_type: Type of lookup ('ip', 'mx', 'ns')
        value: Value to look up
        output_dir: Directory to save CSV files
        verbose: Whether to print detailed progress messages

    Returns:
        Path to the output file
    """
    try:
        lookup_name = {
            'ip': 'IP address',
            'mx': 'MX server',
            'ns': 'NS server'
        }.get(lookup_type, lookup_type)

        print_section(f"Performing reverse {lookup_name} lookup for: {value}")

        # Call appropriate API method
        if lookup_type == 'ip':
            results = api_client.whois_reverse_ip(value)
        elif lookup_type == 'mx':
            results = api_client.whois_reverse_mx(value)
        elif lookup_type == 'ns':
            results = api_client.whois_reverse_ns(value)
        else:
            raise ValueError(f"Unsupported lookup type: {lookup_type}")

        # Create output filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_value = value.replace('.', '_').replace(':', '_')
        output_file = os.path.join(output_dir, f"reverse_{lookup_type}_{safe_value}_{timestamp}.csv")

        # Save results
        if 'domains' in results and results['domains']:
            domains = results['domains']

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Domain', 'Registrar', 'Created', 'Updated', 'Expires'])

                for domain in domains:
                    writer.writerow([
                        domain.get('domain_name', ''),
                        domain.get('registrar', ''),
                        domain.get('creation_date', ''),
                        domain.get('updated_date', ''),
                        domain.get('expiration_date', '')
                    ])

            print_success(f"Found {len(domains)} domains using this {lookup_name}")
            print_info(f"Results saved to: {os.path.basename(output_file)}")

            # Display sample results if verbose
            if verbose and domains:
                print_info("Sample domains:")
                for i, domain in enumerate(domains[:5]):
                    print(f"    - {domain.get('domain_name', 'N/A')}")
                if len(domains) > 5:
                    print(f"    - ... and {len(domains) - 5} more")
        else:
            print_warning(f"No domains found using this {lookup_name}")
            # Create empty file
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Domain', 'Registrar', 'Created', 'Updated', 'Expires'])

        return output_file

    except Exception as e:
        print_error(f"Error performing reverse {lookup_type} lookup: {str(e)}")
        return None


def _save_entries_to_csv(entries: List[Dict], output_path: str) -> None:
    """Save search result entries to a CSV file with improved formatting."""
    if not entries:
        return

    # Determine all possible fields from all entries
    all_fields = set()
    for entry in entries:
        all_fields.update(entry.keys())

    # Remove 'raw_record' if present as it's typically a nested structure
    if 'raw_record' in all_fields:
        all_fields.remove('raw_record')

    # Prioritize important fields first, then add the rest alphabetically
    priority_fields = ['id', 'email', 'username', 'password', 'hashed_password', 
                      'name', 'address', 'phone', 'ip_address', 'database_name']

    # Create ordered fieldnames list
    fieldnames = []
    for field in priority_fields:
        if field in all_fields:
            fieldnames.append(field)
            all_fields.remove(field)

    # Add remaining fields alphabetically
    fieldnames.extend(sorted(list(all_fields)))

    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for entry in entries:
            # Handle list fields by joining them with commas
            row_data = {}
            for field in fieldnames:
                if field in entry:
                    if isinstance(entry[field], list):
                        row_data[field] = ', '.join(str(item) for item in entry[field])
                    else:
                        row_data[field] = entry[field]
                else:
                    row_data[field] = ''

            writer.writerow(row_data)
            
def _save_whois_to_csv(whois_data: Dict, output_path: str) -> None:
    """Save WHOIS data to a CSV file with improved formatting."""
    # Flatten the WHOIS data structure
    flattened_data = _flatten_dict(whois_data)

    # Order the keys for better readability
    priority_keys = ['domain_name', 'registrar', 'creation_date', 'expiration_date', 
                     'updated_date', 'status', 'name_servers']

    ordered_keys = []
    for key in priority_keys:
        if key in flattened_data:
            ordered_keys.append(key)

    # Add remaining keys
    for key in sorted(flattened_data.keys()):
        if key not in ordered_keys:
            ordered_keys.append(key)

    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Field', 'Value'])

        for key in ordered_keys:
            writer.writerow([key, flattened_data[key]])


def _save_whois_history_to_csv(whois_history: Dict, output_path: str) -> None:
    """Save WHOIS history data to a CSV file with improved formatting."""
    records = whois_history.get('records', [])

    if not records:
        return

    # Determine all fields from the first record
    if records and isinstance(records[0], dict):
        all_fields = set()
        for record in records:
            all_fields.update(record.keys())

        # Prioritize important fields
        priority_fields = ['date', 'domain_name', 'registrar', 'creation_date', 
                          'expiration_date', 'updated_date']

        # Create ordered fieldnames
        fieldnames = []
        for field in priority_fields:
            if field in all_fields:
                fieldnames.append(field)
                all_fields.remove(field)

        # Add remaining fields
        fieldnames.extend(sorted(list(all_fields)))

        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for record in records:
                # Process each record
                row_data = {}
                for field in fieldnames:
                    if field in record:
                        if isinstance(record[field], list):
                            row_data[field] = ', '.join(str(item) for item in record[field])
                        else:
                            row_data[field] = record[field]
                    else:
                        row_data[field] = ''

                writer.writerow(row_data)
    else:
        # Fallback if records structure is unexpected
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Raw WHOIS History Data'])
            writer.writerow([json.dumps(whois_history, indent=2)])


def _save_subdomains_to_csv(subdomain_data: Dict, output_path: str) -> None:
    """Save subdomain data to a CSV file with improved formatting."""
    domains = subdomain_data.get('domains', [])

    if not domains:
        return

    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Subdomain', 'IP Address', 'Created', 'Updated'])

        for domain in domains:
            writer.writerow([
                domain.get('domain', ''),
                domain.get('ip', ''),
                domain.get('created', ''),
                domain.get('updated', '')
            ])


def _save_list_to_csv(items: List, headers: List[str], output_path: str) -> None:
    """Save a list of items to a CSV file."""
    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)

        for item in items:
            if isinstance(item, list):
                writer.writerow(item)
            else:
                writer.writerow([item])


def _extract_emails_from_results(entries: List[Dict]) -> List[str]:
    """Extract unique email addresses from search results."""
    emails = set()

    for entry in entries:
        if 'email' in entry and entry['email']:
            if isinstance(entry['email'], list):
                for email in entry['email']:
                    if email and '@' in email:
                        emails.add(email)
            elif isinstance(entry['email'], str) and '@' in entry['email']:
                emails.add(entry['email'])

    return sorted(list(emails))


def _flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
    """Flatten a nested dictionary structure."""
    items = {}
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k

        if isinstance(v, dict):
            items.update(_flatten_dict(v, new_key, sep=sep))
        elif isinstance(v, list):
            if all(isinstance(item, dict) for item in v):
                for i, item in enumerate(v):
                    items.update(_flatten_dict(item, f"{new_key}[{i}]", sep=sep))
            else:
                items[new_key] = ', '.join(str(item) for item in v)
        else:
            items[new_key] = v

    return items


def _format_file_size(size_bytes):
    """Format file size in a human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


def _print_key_whois_details(whois_data):
    """Print key WHOIS details in a readable format."""
    print_info("Key WHOIS details:")

    if 'domain_name' in whois_data:
        print(f"    Domain: {whois_data.get('domain_name', 'N/A')}")
    if 'registrar' in whois_data:
        print(f"    Registrar: {whois_data.get('registrar', 'N/A')}")
    if 'creation_date' in whois_data:
        print(f"    Created: {whois_data.get('creation_date', 'N/A')}")
    if 'expiration_date' in whois_data:
        print(f"    Expires: {whois_data.get('expiration_date', 'N/A')}")

    if 'name_servers' in whois_data:
        ns = whois_data.get('name_servers', [])
        if isinstance(ns, list) and len(ns) > 0:
            print(f"    Name Servers: {ns[0]}" + (f" (+ {len(ns)-1} more)" if len(ns) > 1 else ""))
            
def main():
    """Main function to run the script."""
    parser = argparse.ArgumentParser(
        description='DeHashed Domain Intelligence Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic domain intelligence
  python dehashed_intel.py example.com --api-key YOUR_API_KEY

  # Full domain intelligence (includes WHOIS history)
  python dehashed_intel.py example.com --api-key YOUR_API_KEY --full

  # Reverse WHOIS lookup
  python dehashed_intel.py --api-key YOUR_API_KEY --reverse-whois --include "John Doe,Acme Corp"

  # Reverse IP lookup
  python dehashed_intel.py --api-key YOUR_API_KEY --reverse-ip 8.8.8.8
'''
    )

    # General options
    parser.add_argument('domain', nargs='?', help='Domain to investigate (e.g., example.com)')
    parser.add_argument('--api-key', help='DeHashed API key', required=True)
    parser.add_argument('--output-dir', help='Directory to save results', default='./results')
    parser.add_argument('--quiet', help='Reduce output verbosity', action='store_true')
    parser.add_argument('--no-color', help='Disable colored output', action='store_true')
    parser.add_argument('--version', help='Show version information and exit', action='store_true')

    # Domain intelligence options
    intel_group = parser.add_argument_group('Domain Intelligence Options')
    intel_group.add_argument('--full', help='Enable all intelligence gathering options (includes WHOIS history)', action='store_true')
    intel_group.add_argument('--basic', help='Basic intelligence gathering (no WHOIS history)', action='store_true')
    intel_group.add_argument('--no-breaches', help='Skip data breach search', action='store_true')
    intel_group.add_argument('--no-whois', help='Skip WHOIS lookup', action='store_true')
    intel_group.add_argument('--no-subdomains', help='Skip subdomain scanning', action='store_true')
    intel_group.add_argument('--no-emails', help='Skip email extraction from breach data', action='store_true')
    intel_group.add_argument('--whois-history', help='Include WHOIS history (costs 25 credits)', action='store_true')

    # Reverse lookup options
    reverse_group = parser.add_argument_group('Reverse Lookup Options')
    reverse_group.add_argument('--reverse-whois', help='Perform reverse WHOIS lookup', action='store_true')
    reverse_group.add_argument('--include', help='Terms to include in reverse WHOIS (comma-separated, max 4)')
    reverse_group.add_argument('--exclude', help='Terms to exclude from reverse WHOIS (comma-separated, max 4)')
    reverse_group.add_argument('--historic', help='Use historic data for reverse WHOIS (default: current)', action='store_true')
    reverse_group.add_argument('--reverse-ip', help='Perform reverse IP lookup', metavar='IP')
    reverse_group.add_argument('--reverse-mx', help='Perform reverse MX server lookup', metavar='MX')
    reverse_group.add_argument('--reverse-ns', help='Perform reverse NS server lookup', metavar='NS')

    # Utility options
    util_group = parser.add_argument_group('Utility Options')
    util_group.add_argument('--check-credits', help='Check remaining WHOIS credits and exit', action='store_true')

    args = parser.parse_args()

    # Disable colors if requested or if not in a terminal
    if args.no_color or not sys.stdout.isatty():
        for attr in dir(ConsoleColors):
            if not attr.startswith('__'):
                setattr(ConsoleColors, attr, '')

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Print banner
    if not args.quiet:
        print_banner()

    # Show version and exit
    if args.version:
        print("DeHashed Domain Intelligence Tool v1.0.0")
        print("Copyright (c) 2025")
        sys.exit(0)

    # Initialize the DeHashed API client
    client = DeHashedAPI(args.api_key)

    # Check credits and exit if requested
    if args.check_credits:
        try:
            credits = client.whois_credits()
            if 'whois_credits' in credits:
                print_success(f"You have {credits['whois_credits']} WHOIS credits available")
            else:
                print_warning("Could not determine available credits")
        except Exception as e:
            print_error(f"Error checking credits: {str(e)}")
        sys.exit(0)

    # Determine if we're doing domain intelligence or reverse lookups
    doing_domain_intel = args.domain is not None
    doing_reverse_lookup = args.reverse_whois or args.reverse_ip or args.reverse_mx or args.reverse_ns

    # Validate arguments
    if not doing_domain_intel and not doing_reverse_lookup:
        parser.error("You must specify either a domain for intelligence gathering or a reverse lookup option")

    if args.reverse_whois and not args.include and not args.exclude:
        parser.error("Reverse WHOIS requires at least one include or exclude term")

    # Process domain intelligence if a domain is provided
    if doing_domain_intel:
        # Determine which options to enable
        options = {}

        if args.full:
            # Full scan includes everything
            options = {
                'search_breaches': True,
                'whois': True,
                'whois_history': True,
                'subdomains': True,
                'extract_emails': True
            }
        elif args.basic:
            # Basic scan excludes WHOIS history
            options = {
                'search_breaches': True,
                'whois': True,
                'whois_history': False,
                'subdomains': True,
                'extract_emails': True
            }
        else:
            # Custom options based on flags
            options = {
                'search_breaches': not args.no_breaches,
                'whois': not args.no_whois,
                'whois_history': args.whois_history,
                'subdomains': not args.no_subdomains,
                'extract_emails': not args.no_emails
            }

        # Run the domain intelligence gathering
        domain_intelligence_to_csv(client, args.domain, args.output_dir, options, verbose=not args.quiet)

    # Process reverse WHOIS if requested
    if args.reverse_whois:
        include_terms = args.include.split(',') if args.include else []
        exclude_terms = args.exclude.split(',') if args.exclude else None
        reverse_type = 'historic' if args.historic else 'current'

        perform_reverse_whois(client, include_terms, exclude_terms, reverse_type, args.output_dir, verbose=not args.quiet)

    # Process reverse IP if requested
    if args.reverse_ip:
        perform_reverse_lookup(client, 'ip', args.reverse_ip, args.output_dir, verbose=not args.quiet)

    # Process reverse MX if requested
    if args.reverse_mx:
        perform_reverse_lookup(client, 'mx', args.reverse_mx, args.output_dir, verbose=not args.quiet)

    # Process reverse NS if requested
    if args.reverse_ns:
        perform_reverse_lookup(client, 'ns', args.reverse_ns, args.output_dir, verbose=not args.quiet)


if __name__ == "__main__":
    main()
