# DeHashed Domain Intelligence Tool Documentation

# Overview
The DeHashed Domain Intelligence Tool is a Python utility that leverages the DeHashed API to gather comprehensive intelligence about a domain. It collects data breach information, WHOIS records, subdomain data, and more, organizing everything into CSV files for easy analysis.

This tool is designed for security professionals, threat intelligence analysts, and penetration testers who need to quickly assess a domain's exposure in data breaches and gather intelligence for security assessments.

# Features
-	Comprehensive Data Collection: Gathers multiple types of intelligence about a domain:
-	Data breach records associated with the domain
-	Current WHOIS information
-	Historical WHOIS records
-	Subdomain enumeration
-	Email address extraction
-	Organized Output: All data is saved in CSV format for easy analysis in spreadsheet applications or data processing tools.
-	Summary Report: Generates a text summary of findings for quick assessment.
-	Error Handling: Robust error handling ensures the tool continues even if one API endpoint fails.

# Requirements
-	Python 3.6 or higher
-	Required Python packages:
-	requests
-	argparse
-	DeHashed API key with sufficient credits

# Installation
-	Save the script as dehashed_domain_intel.py
-	Install required dependencies:
  ``` pip install requests ```
-	Ensure you have a valid DeHashed API key with sufficient credits.

# Basic Usage
-	Run the script from the command line with a domain name and your API key:

```
python dehashed_domain_intel.py example.com --api-key YOUR_API_KEY_HERE
```

-	Command-Line Arguments
o	domain (required): The domain to investigate (e.g., example.com)
  ```--api-key``` (required): Your DeHashed API key
  ```--output-dir``` (optional): Directory to save results (default: ./results)

# Output Structure
The tool creates a timestamped directory for each scan with the following structure:

```
results/
└── example_com_20250519_123456/
    ├── domain_search_results.csv   # Data breach records
    ├── extracted_emails.csv        # Unique email addresses found
    ├── subdomains.csv              # Discovered subdomains
    ├── whois_history.csv           # Historical WHOIS data
    ├── whois_info.csv              # Current WHOIS information
    └── summary.txt                 # Overview of findings
```

# CSV File Formats
-	domain_search_results.csv
o	Contains all records from data breaches associated with the domain, including:
o	Email addresses
o	Usernames
o	Passwords (if available)
o	IP addresses
o	Names
o	Other personal information

# extracted_emails.csv
-	A simple list of all unique email addresses found in the data breach records.

# subdomains.csv
-	Lists discovered subdomains with the following columns:
-	Subdomain
-	IP
-	Created
-	Updated

# whois_info.csv and whois_history.csv
-	Contains WHOIS information in a key-value format:
o	Field
o	Value

# Summary File
-	The summary.txt file provides a quick overview of the findings:
-	Total records found
-	Number of unique email addresses
-	Number of subdomains discovered
-	List of generated files

# API Usage and Credit Consumption
This tool uses several DeHashed API endpoints, each consuming different amounts of credits:
-	Search API: 1 credit per search
-	WHOIS Search: 1 credit per lookup
-	WHOIS History: 25 credits per lookup
-	Subdomain Scan: Credit usage varies

Be mindful of your credit balance when using this tool, especially for multiple domains.

# Advanced Usage
Using as a Module
-	You can import the tool in your own Python scripts:
-	from dehashed_domain_intel import DeHashedAPI, domain_intelligence_to_csv

## Initialize the API client

```
api_client = DeHashedAPI("your_api_key_here")
```

## Run the domain intelligence gathering

```
results_dir = domain_intelligence_to_csv(api_client, "example.com", "./custom_output")
print(f"Results saved to: {results_dir}")
```

# Customizing Output
-	You can modify the script to customize the output format or add additional data sources by editing the domain_intelligence_to_csv function.

# Error Handling
-	The tool implements robust error handling to ensure that a failure in one API endpoint doesn't stop the entire process. Each API call is wrapped in a try-except block, and errors are logged to the console.
-	Common errors include:
o	Rate limiting (HTTP 429)
o	Authentication errors (HTTP 401)
o	Insufficient credits (HTTP 403)

# Security Considerations
-	API Key Protection: Your DeHashed API key provides access to sensitive data. Never share it or commit it to public repositories.
-	Data Handling: The data collected may contain sensitive information. Handle it according to your organization's data protection policies.
-	Legal Compliance: Ensure you have proper authorization to gather intelligence on the target domain.

# Troubleshooting

## Rate Limiting
-	If you encounter rate limiting errors (HTTP 429), the script will display:
-	[!] Error searching domain data: 429 Client Error: Too Many Requests
-	Solution: Reduce the frequency of your requests or contact DeHashed support for increased limits.

## Authentication Errors
-	If your API key is invalid or expired:
-	[!] Error searching domain data: 401 Client Error: Unauthorized
-	Solution: Verify your API key or generate a new one from the DeHashed dashboard.

## Insufficient Credits
-	If you don't have enough credits:
-	[!] Error retrieving WHOIS history: 403 Client Error: Forbidden
-	Solution: Purchase additional credits through the DeHashed platform.

## Best Practices
1.	Run during off-hours: To avoid rate limiting, run large scans during off-hours.
2.	Process results offline: Download the results and process them offline to minimize API usage.
3.	Target specific domains: Be selective about which domains you scan to conserve credits.
4.	Regular updates: Run the tool periodically to detect new exposures.

## Limitations
-	The tool is limited by the data available in DeHashed's databases.
-	Some API endpoints consume significant credits (e.g., WHOIS History).
-	Rate limiting may affect large-scale scanning operations.

## Legal Disclaimer
This tool is provided for legitimate security assessment and threat intelligence purposes only. Users are responsible for ensuring they have proper authorization to gather intelligence on target domains and for complying with all applicable laws and regulations.
