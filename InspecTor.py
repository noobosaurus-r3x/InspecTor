#!/usr/bin/env python3
"""
InspecTor.py

A script to extract metadata from websites using optional Tor anonymity.

Author: Noobosaurus R3x
Date: December 2024

Note: I am not a professional developer, and this tool could be improved with your help.
Feel free to fork the repository and enhance it by adding features, fixing bugs, or optimizing the code.
"""

import argparse
import json
import logging
import os
import re
import socket
import sys
import time
import html
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib import robotparser
import sqlite3
from urllib3.util.retry import Retry
from fake_useragent import UserAgent
from datetime import datetime
import phonenumbers
from phonenumbers import NumberParseException
from urllib3.exceptions import InsecureRequestWarning
import urllib3

# Disable insecure request warnings if SSL verification is off.
urllib3.disable_warnings(category=InsecureRequestWarning)

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("The 'colorama' library is required for colored output. Please install it using 'pip install colorama'.")
    sys.exit(1)

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False


def setup_logging():
    """
    Set up the logging configuration.
    Logs are displayed both on stdout and in 'InspecTor.log'.
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('InspecTor.log')
        ]
    )


def setup_argparser():
    """
    Set up command-line argument parsing with options for URLs, files,
    output, SSL verification, Selenium usage, concurrency, database, and fields.
    """
    parser = argparse.ArgumentParser(
        description='Extract metadata from websites using optional Tor anonymity.'
    )
    # One of these two arguments is required
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '-u', '--urls',
        nargs='+',
        help='List of URLs to scrape.'
    )
    group.add_argument(
        '-f', '--file',
        type=str,
        help='Path to a file containing URLs, one per line.'
    )

    parser.add_argument(
        '-o', '--output',
        type=str,
        default='site_metadata.json',
        help='Output JSON file to save metadata (use "-" for stdout).'
    )
    parser.add_argument(
        '--verify-ssl',
        dest='verify_ssl',
        action='store_true',
        help='Enable SSL certificate verification (default: True).'
    )
    parser.add_argument(
        '--no-verify-ssl',
        dest='verify_ssl',
        action='store_false',
        help='Disable SSL certificate verification.'
    )
    parser.set_defaults(verify_ssl=True)
    parser.add_argument(
        '--use-selenium',
        action='store_true',
        help='Use Selenium for handling dynamic content (requires ChromeDriver).'
    )
    parser.add_argument(
        '--max-workers',
        type=int,
        default=5,
        help='Maximum number of concurrent threads (default: 5).'
    )
    parser.add_argument(
        '--database',
        type=str,
        default='metadata.db',
        help='SQLite database file to store metadata (default: metadata.db).'
    )

    # Field extraction options
    extraction_group = parser.add_mutually_exclusive_group()
    extraction_group.add_argument(
        '--fields',
        nargs='+',
        help='Specify which metadata fields to extract. '
             'Available fields: url, title, description, keywords, og_title, og_description, '
             'timestamp, headers, images, scripts, css_files, social_links, '
             'csp, server_technologies, crypto_wallets, links, emails, external_links, '
             'http_headers, phone_numbers.'
    )
    extraction_group.add_argument(
        '--extract-all',
        action='store_true',
        help='Extract all available metadata fields.'
    )

    parser.add_argument(
        '--human-readable', '-hr',
        action='store_true',
        help='Output the results in a human-readable format.'
    )
    parser.add_argument(
        '--force-tor',
        action='store_true',
        help='Route all traffic through Tor, even for regular URLs.'
    )
    parser.add_argument(
        '--default-region',
        type=str,
        default=None,
        help='Default region code for parsing phone numbers (e.g., "FR" for France).'
    )
    return parser


def load_urls_from_file(file_path):
    """
    Load URLs from a text file, one per line.
    If the file is not found, the script exits.
    """
    if not os.path.isfile(file_path):
        logging.error(f"The file '{file_path}' does not exist.")
        sys.exit(1)
    with open(file_path, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    return urls


def setup_session(verify_ssl=True, use_tor=False):
    """
    Set up a requests session with optional Tor proxy and a retry strategy.
    Also sets a random or fallback User-Agent header.
    """
    session = requests.Session()
    if use_tor:
        session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }

    # Configure retries for robustness
    retries = HTTPAdapter(max_retries=Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    ))
    session.mount('http://', retries)
    session.mount('https://', retries)

    # Handle SSL verification if disabled
    session.verify = verify_ssl

    # Try to use a randomized User-Agent to avoid easy fingerprinting
    ua = UserAgent()
    try:
        session.headers.update({'User-Agent': ua.random})
    except Exception as e:
        logging.warning(f"Failed to retrieve a random User-Agent. Falling back to default. Error: {e}")
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                              'AppleWebKit/537.36 (KHTML, like Gecko) '
                                              'Chrome/91.0.4472.124 Safari/537.36'})
    return session


def is_tor_port_open(host='127.0.0.1', port=9050):
    """
    Check if the Tor SOCKS5 proxy port is open.
    This ensures Tor is running and accessible.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        try:
            s.connect((host, port))
            logging.info(f"Tor SOCKS5 proxy is listening on {host}:{port}.")
            return True
        except socket.error:
            logging.error(f"Cannot connect to Tor SOCKS5 proxy on {host}:{port}.")
            return False


def is_valid_url(url):
    """
    Validate the URL's scheme and netloc to ensure it's well-formed.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        if not parsed.netloc:
            return False
        return True
    except Exception:
        return False


def extract_phone_numbers(page_text, default_region=None):
    """
    Extract phone numbers from page text using the phonenumbers library.
    This tries to parse and format phone numbers found in the text.
    """
    potential_numbers = re.findall(r'\+?\d[\d\s().-]{7,}\d', page_text)
    phone_numbers_list = []
    for number in potential_numbers:
        try:
            parsed_number = phonenumbers.parse(number, default_region)
            if phonenumbers.is_valid_number(parsed_number):
                formatted_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
                phone_numbers_list.append(formatted_number)
        except NumberParseException:
            continue
    return list(set(phone_numbers_list)) if phone_numbers_list else None


def decode_email(encoded_str):
    """
    Decode HTML-escaped strings. This is useful if email addresses are obfuscated.
    """
    decoded_str = html.unescape(encoded_str)
    return decoded_str


def try_selenium(url, use_tor):
    """
    Attempt to use Selenium with a headless Chrome browser to render dynamic content.
    If Selenium or ChromeDriver is not available, or if any error occurs, this returns (None, None),
    indicating that the code should fall back to the requests library.
    """
    if not SELENIUM_AVAILABLE:
        logging.warning("Selenium is not available. Falling back to requests only.")
        return None, None

    options = Options()
    # Use the recommended '--headless' flag for newer Chrome versions
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')

    if use_tor:
        options.add_argument('--proxy-server=socks5://127.0.0.1:9050')

    try:
        driver = webdriver.Chrome(options=options)
    except Exception as e:
        logging.warning(f"Unable to start Selenium Chrome WebDriver: {e}. Falling back to requests only.")
        return None, None

    try:
        driver.set_page_load_timeout(30)
        driver.get(url)
        # Wait for JS to load some content
        time.sleep(5)
        page_source = driver.page_source
        driver.quit()
        soup = BeautifulSoup(page_source, 'html.parser')
        # Selenium doesn't provide direct access to response headers
        # so we return empty for headers
        response_headers = {}
        return soup, response_headers
    except Exception as e:
        logging.error(f"Selenium failed to retrieve {url}: {e}")
        driver.quit()
        return None, None


def extract_metadata(url, args, fields=None, default_region=None):
    """
    Extract metadata from a given URL. Uses requests or Selenium based on args.
    Fields to extract can be specified, or '--extract-all' can be used for everything.
    If the URL is an onion domain or Tor is forced, requests go through Tor.
    """
    is_onion = urlparse(url).netloc.endswith('.onion')
    use_tor = is_onion or args.force_tor
    session = setup_session(verify_ssl=args.verify_ssl, use_tor=use_tor)

    # Define all possible fields for future reference
    all_possible_fields = {
        'url', 'title', 'description', 'keywords', 'og_title', 'og_description',
        'timestamp', 'headers', 'images', 'scripts', 'css_files',
        'social_links', 'csp', 'server_technologies', 'crypto_wallets',
        'links', 'emails', 'external_links', 'http_headers', 'phone_numbers'
    }

    # Determine which fields we want to extract
    if args.extract_all:
        fields_to_extract = all_possible_fields
    else:
        if fields is None:
            # Default fields if none provided
            fields_to_extract = {
                'url', 'title', 'description', 'keywords',
                'og_title', 'og_description', 'timestamp', 'http_headers'
            }
        else:
            invalid_fields = set(fields) - all_possible_fields
            if invalid_fields:
                logging.warning(f"Invalid fields specified for extraction: {', '.join(invalid_fields)}")
                fields_to_extract = set(fields) - invalid_fields
            else:
                fields_to_extract = set(fields)

    # Attempt Selenium if requested
    if args.use_selenium:
        soup, response_headers = try_selenium(url, use_tor)
        if soup is None:
            # If Selenium failed, fallback to requests
            try:
                response = session.get(url, timeout=15)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
                response_headers = dict(response.headers)
            except requests.exceptions.RequestException as e:
                logging.error(f"Connection error accessing {url}: {e}")
                return None
    else:
        # If Selenium not requested, use requests directly
        try:
            response = session.get(url, timeout=15)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            response_headers = dict(response.headers)
        except requests.exceptions.RequestException as e:
            logging.error(f"Connection error accessing {url}: {e}")
            return None

    metadata = {}
    page_text = soup.get_text()

    # Extracting fields one by one, checking if they are requested
    if 'url' in fields_to_extract:
        metadata['url'] = url
    if 'title' in fields_to_extract:
        metadata['title'] = soup.title.string.strip() if soup.title and soup.title.string else None
    if 'description' in fields_to_extract:
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        metadata['description'] = meta_desc.get('content', '').strip() if meta_desc else None
    if 'keywords' in fields_to_extract:
        meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
        metadata['keywords'] = meta_keywords.get('content', '').strip() if meta_keywords else None
    if 'og_title' in fields_to_extract:
        og_title = soup.find('meta', property='og:title')
        metadata['og_title'] = og_title.get('content', '').strip() if og_title else None
    if 'og_description' in fields_to_extract:
        og_description = soup.find('meta', property='og:description')
        metadata['og_description'] = og_description.get('content', '').strip() if og_description else None
    if 'timestamp' in fields_to_extract:
        metadata['timestamp'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    if 'http_headers' in fields_to_extract:
        metadata['http_headers'] = response_headers if response_headers else None

    # Additional fields that require more complex extraction logic
    if fields_to_extract.intersection({
        'headers', 'images', 'scripts', 'css_files',
        'social_links', 'csp', 'server_technologies', 'crypto_wallets',
        'links', 'emails', 'external_links', 'phone_numbers'
    }):
        if 'headers' in fields_to_extract:
            # Extract h1, h2, h3 headers
            headers_list = [header.get_text(strip=True) for header in soup.find_all(['h1', 'h2', 'h3'])]
            metadata['headers'] = headers_list if headers_list else None
        if 'images' in fields_to_extract:
            # Extract images and their alt attributes
            images_list = [{'src': img.get('src'), 'alt': (img.get('alt', '') or '').strip()}
                           for img in soup.find_all('img', src=True)]
            metadata['images'] = images_list if images_list else None
        if 'scripts' in fields_to_extract:
            # Extract external scripts
            scripts_list = [script['src'] for script in soup.find_all('script', src=True)]
            metadata['scripts'] = scripts_list if scripts_list else None
        if 'css_files' in fields_to_extract:
            # Extract CSS files
            css_files_list = [link['href'] for link in soup.find_all('link', rel='stylesheet')]
            metadata['css_files'] = css_files_list if css_files_list else None
        if 'social_links' in fields_to_extract:
            # Extract social media links by matching known platforms
            social_links_list = [a['href'] for a in soup.find_all('a', href=True)
                                 if any(platform in a['href'] for platform in ['twitter.com', 'facebook.com', 'linkedin.com'])]
            metadata['social_links'] = social_links_list if social_links_list else None
        if 'csp' in fields_to_extract:
            # Extract Content-Security-Policy meta tag if available
            csp = soup.find('meta', attrs={'http-equiv': 'Content-Security-Policy'})
            metadata['csp'] = csp['content'] if csp else None
        if 'server_technologies' in fields_to_extract:
            # Identify server technologies from headers
            server_technologies = {}
            if response_headers:
                if 'Server' in response_headers:
                    server_technologies['server'] = response_headers.get('Server')
                if 'X-Powered-By' in response_headers:
                    server_technologies['powered_by'] = response_headers.get('X-Powered-By')
            metadata['server_technologies'] = server_technologies if server_technologies else None
        if 'crypto_wallets' in fields_to_extract:
            # Extract various crypto wallet addresses from the page text
            crypto_wallets = {}
            # Bitcoin addresses
            bitcoin_addresses = re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', page_text)
            if bitcoin_addresses:
                crypto_wallets['bitcoin'] = list(set(bitcoin_addresses))
            # Ethereum addresses
            ethereum_addresses = re.findall(r'\b0x[a-fA-F0-9]{40}\b', page_text)
            if ethereum_addresses:
                crypto_wallets['ethereum'] = list(set(ethereum_addresses))
            # Litecoin addresses
            litecoin_legacy = re.findall(r'\b[L,M][a-km-zA-HJ-NP-Z1-9]{26,33}\b', page_text)
            litecoin_bech32 = re.findall(r'\bltc1[a-z0-9]{39}\b', page_text)
            if litecoin_legacy or litecoin_bech32:
                crypto_wallets['litecoin'] = list(set(litecoin_legacy + litecoin_bech32))
            # Dogecoin addresses
            dogecoin_addresses = re.findall(r'\bD{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}\b', page_text)
            if dogecoin_addresses:
                crypto_wallets['dogecoin'] = list(set(dogecoin_addresses))
            # Bitcoin Cash
            bch_legacy = re.findall(r'\b[L,M][a-km-zA-HJ-NP-Z1-9]{26,33}\b', page_text)
            bch_cashaddr = re.findall(r'\b(q|p)[a-z0-9]{41}\b', page_text)
            if bch_legacy or bch_cashaddr:
                crypto_wallets['bitcoin_cash'] = list(set(bch_legacy + bch_cashaddr))
            # Dash
            dash_addresses = re.findall(r'\b[X,7][a-km-zA-HJ-NP-Z1-9]{26,33}\b', page_text)
            if dash_addresses:
                crypto_wallets['dash'] = list(set(dash_addresses))
            # Monero
            monero_standard = re.findall(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b', page_text)
            monero_integrated = re.findall(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{105}\b', page_text)
            if monero_standard or monero_integrated:
                crypto_wallets['monero'] = list(set(monero_standard + monero_integrated))
            # Ripple
            ripple_addresses = re.findall(r'\br[0-9A-Za-z]{24,34}\b', page_text)
            if ripple_addresses:
                crypto_wallets['ripple'] = list(set(ripple_addresses))
            # Zcash
            zcash_transparent = re.findall(r'\bt[1,3][a-km-zA-HJ-NP-Z1-9]{33}\b', page_text)
            zcash_shielded = re.findall(r'\bzs[a-z0-9]{93}\b', page_text)
            if zcash_transparent or zcash_shielded:
                crypto_wallets['zcash'] = list(set((zcash_transparent + zcash_shielded)))
            # Binance Coin
            binance_chain = re.findall(r'\bbnb1[a-z0-9]{38}\b', page_text)
            binance_smart = ethereum_addresses
            if binance_chain or binance_smart:
                combined_binance = list(set(binance_chain + binance_smart)) if binance_smart else binance_chain
                crypto_wallets['binance_coin'] = combined_binance
            # Cardano
            cardano_addresses = re.findall(r'\baddr1[a-z0-9]{58}\b', page_text)
            if cardano_addresses:
                crypto_wallets['cardano'] = list(set(cardano_addresses))
            # Stellar
            stellar_addresses = re.findall(r'\bG[A-Z2-7]{55}\b', page_text)
            if stellar_addresses:
                crypto_wallets['stellar'] = list(set(stellar_addresses))
            # Tether
            tether_omni = re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{26,33}\b', page_text)
            tether_erc20 = ethereum_addresses
            tether_trc20 = re.findall(r'\bT[a-z0-9]{33}\b', page_text)
            tether_combined = tether_omni + tether_erc20 + tether_trc20 if tether_erc20 else tether_omni + tether_trc20
            if tether_combined:
                crypto_wallets['tether'] = list(set(tether_combined))
            # Solana
            solana_addresses = re.findall(r'\b[A-HJ-NP-Za-km-z1-9]{43,44}\b', page_text)
            if solana_addresses:
                crypto_wallets['solana'] = list(set(solana_addresses))
            # Polkadot addresses (corrected pattern)
            polkadot_addresses = re.findall(r'\b1[a-z0-9]{46}\b', page_text)
            if polkadot_addresses:
                crypto_wallets['polkadot'] = list(set(polkadot_addresses))
            # Chainlink
            chainlink_addresses = ethereum_addresses
            if chainlink_addresses:
                crypto_wallets['chainlink'] = list(set(chainlink_addresses))
            # Ethereum Classic
            etc_addresses = ethereum_addresses
            if etc_addresses:
                crypto_wallets['ethereum_classic'] = list(set(etc_addresses))

            metadata['crypto_wallets'] = crypto_wallets if crypto_wallets else None

        if 'links' in fields_to_extract or 'external_links' in fields_to_extract:
            # Distinguish between internal and external links
            internal_links = []
            external_links_list = []
            base_netloc = urlparse(url).netloc
            for a in soup.find_all('a', href=True):
                href = a['href']
                parsed_href = urlparse(urljoin(url, href))
                if base_netloc == parsed_href.netloc:
                    internal_links.append(href)
                else:
                    external_links_list.append(href)
            if 'links' in fields_to_extract and internal_links:
                metadata['links'] = internal_links
            if 'external_links' in fields_to_extract and external_links_list:
                metadata['external_links'] = external_links_list

        if 'emails' in fields_to_extract:
            # Extract emails from text and mailto links
            emails = set()
            text_emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', page_text)
            emails.update(text_emails)
            # Extract emails from mailto links
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if 'mailto:' in href:
                    email = href.split('mailto:')[-1]
                    email = decode_email(email)
                    emails.add(email)
            # Extract reversed emails if present in custom tags
            for span in soup.find_all('span', {'class': 'odEmail'}):
                user = span.get('data-user', '')
                website = span.get('data-website', '')
                if user and website:
                    user = user[::-1]
                    website = website[::-1]
                    email = f"{user}@{website}"
                    emails.add(email)
            metadata['emails'] = list(emails) if emails else None

        if 'phone_numbers' in fields_to_extract:
            # Extract phone numbers
            phone_numbers_found = extract_phone_numbers(page_text, default_region=default_region)
            metadata['phone_numbers'] = phone_numbers_found if phone_numbers_found else None

    if metadata:
        logging.info(f"Metadata extracted from {url}")
        return metadata
    else:
        logging.error(f"No metadata extracted from {url}")
        return None


def setup_database(db_path='metadata.db'):
    """
    Set up a SQLite database to store metadata.
    Create a table if it does not already exist.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metadata (
            url TEXT PRIMARY KEY,
            title TEXT,
            description TEXT,
            keywords TEXT,
            og_title TEXT,
            og_description TEXT,
            timestamp TEXT,
            headers TEXT,
            images TEXT,
            scripts TEXT,
            css_files TEXT,
            social_links TEXT,
            csp TEXT,
            server_technologies TEXT,
            crypto_wallets TEXT,
            links TEXT,
            emails TEXT,
            external_links TEXT,
            http_headers TEXT,
            phone_numbers TEXT
        )
    ''')
    conn.commit()
    return conn


def save_to_database(conn, metadata):
    """
    Save extracted metadata to the SQLite database.
    JSON fields are stored as JSON-encoded strings for complex fields.
    If a record with the same URL exists, it is replaced.
    """
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO metadata
        (url, title, description, keywords, og_title, og_description, timestamp, headers, images, scripts, css_files, social_links, csp, server_technologies, crypto_wallets, links, emails, external_links, http_headers, phone_numbers)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        metadata.get('url', ''),
        metadata.get('title', ''),
        metadata.get('description', ''),
        metadata.get('keywords', ''),
        metadata.get('og_title', ''),
        metadata.get('og_description', ''),
        metadata.get('timestamp', ''),
        json.dumps(metadata.get('headers', [])),
        json.dumps(metadata.get('images', [])),
        json.dumps(metadata.get('scripts', [])),
        json.dumps(metadata.get('css_files', [])),
        json.dumps(metadata.get('social_links', [])),
        metadata.get('csp', ''),
        json.dumps(metadata.get('server_technologies', {})),
        json.dumps(metadata.get('crypto_wallets', {})),
        json.dumps(metadata.get('links', [])),
        json.dumps(metadata.get('emails', [])),
        json.dumps(metadata.get('external_links', [])),
        json.dumps(metadata.get('http_headers', {})),
        json.dumps(metadata.get('phone_numbers', []))
    ))
    conn.commit()


def print_human_readable(metadata_list):
    """
    Print metadata results in a more human-readable format.
    Uses colors to distinguish keys and values, skipping empty fields.
    """
    for metadata in metadata_list:
        print(Fore.CYAN + "\n" + "=" * 80 + "\n")
        for key, value in metadata.items():
            if value:
                if isinstance(value, dict):
                    print(Fore.YELLOW + f"{key.capitalize()}:" + Style.RESET_ALL)
                    for sub_key, sub_value in value.items():
                        if sub_value:
                            print(f"  {Fore.GREEN}{sub_key}:{Style.RESET_ALL} {sub_value}")
                elif isinstance(value, list):
                    print(Fore.YELLOW + f"{key.capitalize()}:" + Style.RESET_ALL)
                    for item in value:
                        if item:
                            if isinstance(item, dict):
                                for sub_key, sub_value in item.items():
                                    if sub_value:
                                        print(f"  {Fore.GREEN}{sub_key}:{Style.RESET_ALL} {sub_value}")
                            else:
                                print(f"  - {Fore.WHITE}{item}{Style.RESET_ALL}")
                else:
                    print(Fore.YELLOW + f"{key.capitalize()}:{Style.RESET_ALL} {Fore.WHITE}{value}{Style.RESET_ALL}")
        print(Fore.CYAN + "\n" + "=" * 80)


def main():
    """
    The main function orchestrates:
    1. Argument parsing and validation.
    2. URL loading and validation.
    3. Checking Tor availability if needed.
    4. Setting up the database.
    5. Concurrently extracting metadata from URLs.
    6. Saving results to JSON or stdout.
    7. Optionally printing results in a human-readable format.
    """
    setup_logging()
    parser = setup_argparser()
    args = parser.parse_args()

    # Load URLs from command line or file
    if args.urls:
        urls = args.urls
    else:
        urls = load_urls_from_file(args.file)

    # Validate URLs and normalize them
    valid_urls = []
    for url in urls:
        normalized_url = url.rstrip('/')
        if is_valid_url(normalized_url):
            valid_urls.append(normalized_url)
        else:
            logging.warning(f"Invalid URL skipped: {url}")

    if not valid_urls:
        logging.error("No valid URLs provided. Exiting.")
        sys.exit(1)

    # Determine fields to extract
    if args.extract_all:
        fields = list({
            'url', 'title', 'description', 'keywords', 'og_title', 'og_description',
            'timestamp', 'headers', 'images', 'scripts', 'css_files',
            'social_links', 'csp', 'server_technologies', 'crypto_wallets',
            'links', 'emails', 'external_links', 'http_headers', 'phone_numbers'
        })
    elif args.fields:
        fields = args.fields
    else:
        fields = None

    # Check if Tor is required
    tor_required = any(urlparse(u).netloc.endswith('.onion') for u in valid_urls) or args.force_tor
    if tor_required and not is_tor_port_open():
        logging.error("Tor SOCKS5 proxy is not accessible. Please ensure Tor is running.")
        sys.exit(1)

    # Set up database connection
    conn = setup_database(args.database)

    # Use ThreadPoolExecutor for concurrency
    results = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        future_to_url = {
            executor.submit(
                extract_metadata,
                url,
                args,
                fields,
                default_region=args.default_region
            ): url for url in valid_urls
        }
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                metadata = future.result()
                if metadata:
                    save_to_database(conn, metadata)
                    results.append(metadata)
                else:
                    logging.error(f"Failed to extract metadata for {url}")
            except Exception as exc:
                logging.error(f"{url} generated an exception: {exc}")

    # Save results to file or stdout
    try:
        if args.output == '-':
            # Print to stdout as JSON
            json.dump(results, sys.stdout, indent=4)
        else:
            # Save to a file in JSON format
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=4)
            logging.info(f"Metadata extraction completed. Results saved to '{args.output}'.")
    except Exception as e:
        logging.error(f"Error saving results to '{args.output}': {e}")

    # Print human-readable output if requested
    if args.human_readable:
        print("\nHuman-readable Output:")
        print_human_readable(results)

    # Close the database connection
    conn.close()


if __name__ == "__main__":
    main()

