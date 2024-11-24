#!/usr/bin/env python3
"""
InspecTor.py

A script to extract metadata from websites using optional Tor anonymity.

Author: Noobosaurus R3x
Date: November 2024

Usage:
    python3 InspecTor.py -u https://example.com https://exampleonionsite1.onion
    python3 InspecTor.py -f urls.txt
    python3 InspecTor.py -u https://example.com -o metadata.json --no-verify-ssl --use-selenium --fields emails
    python3 InspecTor.py -u https://example.com --human-readable
    python3 InspecTor.py -u https://example.com -o - | jq '.'
    python3 InspecTor.py -u https://example.com --force-tor

Field Extraction Options:
    --fields [FIELDS [FIELDS ...]]
                        Specify which metadata fields to extract. Available fields:
                        emails, phone_numbers, links, external_links, images, scripts, css_files,
                        social_links, csp, server_technologies, crypto_wallets,
                        headers, title, description, keywords, og_title, og_description,
                        timestamp, http_headers
                        If not specified, all default metadata is extracted.

    --extract-all      Extract all available metadata fields.

Examples:
    Extract only emails:
        python3 InspecTor.py -u https://example.com --fields emails -o emails.json

    Extract emails and links:
        python3 InspecTor.py -u https://example.com --fields emails links -o data.json

    Extract emails and phone numbers:
        python3 InspecTor.py -u https://example.com --fields emails phone_numbers -o contact_info.json

    Extract all metadata:
        python3 InspecTor.py -u https://example.com --extract-all -o all_metadata.json

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
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from urllib import robotparser
import sqlite3
from urllib3.util.retry import Retry
from fake_useragent import UserAgent
from datetime import datetime
import phonenumbers
from phonenumbers import NumberParseException

# Suppress only the single warning from urllib3 needed.
from urllib3.exceptions import InsecureRequestWarning
import urllib3

urllib3.disable_warnings(category=InsecureRequestWarning)

# Import colorama for colored console output
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("The 'colorama' library is required for colored output. Please install it using 'pip install colorama'.")
    sys.exit(1)


def setup_logging():
    """
    Configures the logging settings for the script.
    Logs are printed to the console and saved to 'InspecTor.log'.
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
    Sets up the command-line argument parser.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description='Extract metadata from websites using optional Tor anonymity.'
    )
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
        help='Use Selenium for handling dynamic content.'
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
        help='Specify which metadata fields to extract. Available fields: url, title, description, keywords, og_title, og_description, timestamp, headers, images, scripts, css_files, social_links, csp, server_technologies, crypto_wallets, links, emails, external_links, http_headers, phone_numbers'
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
    Loads URLs from a specified file.

    Args:
        file_path (str): Path to the file containing URLs.

    Returns:
        list: A list of URLs.
    """
    if not os.path.isfile(file_path):
        logging.error(f"The file '{file_path}' does not exist.")
        sys.exit(1)
    with open(file_path, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    return urls


def setup_session(verify_ssl=True, use_tor=False):
    """
    Sets up a requests session with optional Tor SOCKS5 proxy and retry strategy.

    Args:
        verify_ssl (bool): Whether to verify SSL certificates.
        use_tor (bool): Whether to route traffic through Tor.

    Returns:
        requests.Session: Configured session object.
    """
    session = requests.Session()
    if use_tor:
        session.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }

    # Setup retries with exponential backoff
    retries = HTTPAdapter(max_retries=Retry(
        total=3,
        backoff_factor=2,  # Exponential backoff
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    ))
    session.mount('http://', retries)
    session.mount('https://', retries)

    # Handle SSL verification
    session.verify = verify_ssl

    # Randomize User-Agent header with fallback
    ua = UserAgent()
    try:
        session.headers.update({'User-Agent': ua.random})
    except Exception as e:
        logging.warning(f"Failed to retrieve a random User-Agent. Falling back to default. Error: {e}")
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                                              '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'})
    return session


def is_tor_port_open(host='127.0.0.1', port=9050):
    """
    Checks if the Tor SOCKS5 proxy port is open.

    Args:
        host (str): Host address to check.
        port (int): Port number to check.

    Returns:
        bool: True if port is open, False otherwise.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)  # 5 seconds timeout
        try:
            s.connect((host, port))
            logging.info(f"Tor SOCKS5 proxy is listening on {host}:{port}.")
            return True
        except socket.error:
            logging.error(f"Cannot connect to Tor SOCKS5 proxy on {host}:{port}.")
            return False


def is_valid_url(url):
    """
    Validates if the provided URL is properly formatted.

    Args:
        url (str): URL to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        parsed = urlparse(url)
        # Check if the URL has a valid scheme and netloc
        if parsed.scheme not in ('http', 'https'):
            return False
        if not parsed.netloc:
            return False
        return True
    except Exception:
        return False


def extract_phone_numbers(page_text, default_region=None):
    """
    Extracts phone numbers from the given text using the phonenumbers library.

    Args:
        page_text (str): Text content of the page.
        default_region (str): Default region code (e.g., 'FR' for France).

    Returns:
        list or None: A list of extracted phone numbers or None if none found.
    """
    potential_numbers = re.findall(r'\+?\d[\d\s().-]{7,}\d', page_text)
    phone_numbers = []
    for number in potential_numbers:
        try:
            parsed_number = phonenumbers.parse(number, default_region)
            if phonenumbers.is_valid_number(parsed_number):
                formatted_number = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
                phone_numbers.append(formatted_number)
        except NumberParseException:
            continue
    # Remove duplicates
    return list(set(phone_numbers)) if phone_numbers else None

def decode_email(encoded_str):
    """
    Decodes HTML character references and handles reversed strings if necessary.
    """
    # Decode HTML character references
    decoded_str = html.unescape(encoded_str)
    return decoded_str
    
def extract_metadata(url, use_selenium=False, fields=None, default_region=None):
    """
    Extracts metadata from a given URL.

    Args:
        url (str): The URL to scrape.
        use_selenium (bool): Whether to use Selenium for dynamic content.
        fields (list or None): List of specific fields to extract.
        default_region (str): Default region code for parsing phone numbers.

    Returns:
        dict or None: A dictionary of extracted metadata or None if an error occurs.
    """
    is_onion = urlparse(url).netloc.endswith('.onion')
    use_tor = is_onion or args.force_tor
    session = setup_session(verify_ssl=args.verify_ssl, use_tor=use_tor)
    try:
        if use_selenium:
            # Setup Selenium with headless Chrome
            options = Options()
            options.headless = True
            options.add_argument('--disable-gpu')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            if use_tor:
                options.add_argument('--proxy-server=socks5://127.0.0.1:9050')  # Route traffic through Tor

            with webdriver.Chrome(options=options) as driver:
                driver.set_page_load_timeout(30)
                driver.get(url)

                time.sleep(5)  # Wait for JavaScript to load
                html = driver.page_source
                soup = BeautifulSoup(html, 'html.parser')

                # Since we don't have response headers with Selenium, set them to empty
                response_headers = {}
        else:
            response = session.get(url, timeout=15)  # Increased timeout for potential delays
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            response_headers = dict(response.headers)

        metadata = {}
        page_text = soup.get_text()

        # Define all possible fields
        all_possible_fields = {
            'url', 'title', 'description', 'keywords', 'og_title', 'og_description',
            'timestamp', 'headers', 'images', 'scripts', 'css_files',
            'social_links', 'csp', 'server_technologies', 'crypto_wallets',
            'links', 'emails', 'external_links', 'http_headers', 'phone_numbers'
        }

        # If fields is None, extract all default metadata
        if fields is None:
            fields_to_extract = {
                'url', 'title', 'description', 'keywords', 'og_title', 'og_description',
                'timestamp', 'http_headers'
            }
        else:
            # Validate fields
            invalid_fields = set(fields) - all_possible_fields
            if invalid_fields:
                logging.warning(f"Invalid fields specified for extraction: {', '.join(invalid_fields)}")
                fields_to_extract = set(fields) - invalid_fields
            else:
                fields_to_extract = set(fields)

        # Extract specified fields
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

        if fields_to_extract.intersection({'headers', 'images', 'scripts', 'css_files',
                                           'social_links', 'csp', 'server_technologies',
                                           'crypto_wallets', 'links', 'emails', 'external_links', 'phone_numbers'}):
            # Extract additional metadata
            if fields_to_extract.intersection({'headers', 'images', 'scripts', 'css_files',
                                               'social_links', 'csp', 'server_technologies',
                                               'crypto_wallets'}):
                # Extract headers (h1, h2, h3)
                if 'headers' in fields_to_extract:
                    headers = [header.get_text(strip=True) for header in soup.find_all(['h1', 'h2', 'h3'])]
                    metadata['headers'] = headers if headers else None

                # Extract images (src and alt)
                if 'images' in fields_to_extract:
                    images = [{'src': img.get('src'), 'alt': img.get('alt', '').strip()} for img in soup.find_all('img', src=True)]
                    metadata['images'] = images if images else None

                # Extract scripts and CSS files
                if 'scripts' in fields_to_extract:
                    scripts = [script['src'] for script in soup.find_all('script', src=True)]
                    metadata['scripts'] = scripts if scripts else None

                if 'css_files' in fields_to_extract:
                    css_files = [link['href'] for link in soup.find_all('link', rel='stylesheet')]
                    metadata['css_files'] = css_files if css_files else None

                # Extract social media links
                if 'social_links' in fields_to_extract:
                    social_links = [a['href'] for a in soup.find_all('a', href=True) if any(platform in a['href'] for platform in ['twitter.com', 'facebook.com', 'linkedin.com'])]
                    metadata['social_links'] = social_links if social_links else None

                # Extract Content-Security-Policy (CSP)
                if 'csp' in fields_to_extract:
                    csp = soup.find('meta', attrs={'http-equiv': 'Content-Security-Policy'})
                    metadata['csp'] = csp['content'] if csp else None

                # Extract server technologies
                if 'server_technologies' in fields_to_extract:
                    server_technologies = {}
                    if response_headers:
                        if 'Server' in response_headers:
                            server_technologies['server'] = response_headers.get('Server')
                        if 'X-Powered-By' in response_headers:
                            server_technologies['powered_by'] = response_headers.get('X-Powered-By')
                    metadata['server_technologies'] = server_technologies if server_technologies else None

                # Extract cryptocurrency wallet addresses
                if 'crypto_wallets' in fields_to_extract:
                    crypto_wallets = {}

                    # Bitcoin
                    bitcoin_addresses = re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', page_text)
                    if bitcoin_addresses:
                        crypto_wallets['bitcoin'] = bitcoin_addresses

                    # Ethereum
                    ethereum_addresses = re.findall(r'\b0x[a-fA-F0-9]{40}\b', page_text)
                    if ethereum_addresses:
                        crypto_wallets['ethereum'] = ethereum_addresses

                    # Litecoin
                    litecoin_legacy = re.findall(r'\b[L,M][a-km-zA-HJ-NP-Z1-9]{26,33}\b', page_text)
                    litecoin_bech32 = re.findall(r'\bltc1[a-z0-9]{39}\b', page_text)
                    if litecoin_legacy or litecoin_bech32:
                        crypto_wallets['litecoin'] = litecoin_legacy + litecoin_bech32

                    # Dogecoin
                    dogecoin_addresses = re.findall(r'\bD{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}\b', page_text)
                    if dogecoin_addresses:
                        crypto_wallets['dogecoin'] = dogecoin_addresses

                    # Bitcoin Cash
                    bch_legacy = re.findall(r'\b[L,M][a-km-zA-HJ-NP-Z1-9]{26,33}\b', page_text)
                    bch_cashaddr = re.findall(r'\b(q|p)[a-z0-9]{41}\b', page_text)
                    if bch_legacy or bch_cashaddr:
                        crypto_wallets['bitcoin_cash'] = bch_legacy + bch_cashaddr

                    # Dash
                    dash_addresses = re.findall(r'\b[X,7][a-km-zA-HJ-NP-Z1-9]{26,33}\b', page_text)
                    if dash_addresses:
                        crypto_wallets['dash'] = dash_addresses

                    # Monero
                    monero_standard = re.findall(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b', page_text)
                    monero_integrated = re.findall(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{105}\b', page_text)
                    if monero_standard or monero_integrated:
                        crypto_wallets['monero'] = monero_standard + monero_integrated

                    # Ripple
                    ripple_addresses = re.findall(r'\br[0-9A-Za-z]{24,34}\b', page_text)
                    if ripple_addresses:
                        crypto_wallets['ripple'] = ripple_addresses

                    # Zcash
                    zcash_transparent = re.findall(r'\bt[1,3][a-km-zA-HJ-NP-Z1-9]{33}\b', page_text)
                    zcash_shielded = re.findall(r'\bzs[a-z0-9]{93}\b', page_text)
                    if zcash_transparent or zcash_shielded:
                        crypto_wallets['zcash'] = zcash_transparent + zcash_shielded

                    # Binance Coin
                    binance_chain = re.findall(r'\bbnb1[a-z0-9]{38}\b', page_text)
                    binance_smart = re.findall(r'\b0x[a-fA-F0-9]{40}\b', page_text)
                    if binance_chain or binance_smart:
                        crypto_wallets['binance_coin'] = binance_chain + binance_smart

                    # Cardano
                    cardano_addresses = re.findall(r'\baddr1[a-z0-9]{58}\b', page_text)
                    if cardano_addresses:
                        crypto_wallets['cardano'] = cardano_addresses

                    # Stellar
                    stellar_addresses = re.findall(r'\bG[A-Z2-7]{55}\b', page_text)
                    if stellar_addresses:
                        crypto_wallets['stellar'] = stellar_addresses

                    # Tether
                    tether_omni = re.findall(r'\b[13][a-km-zA-HJ-NP-Z1-9]{26,33}\b', page_text)
                    tether_erc20 = re.findall(r'\b0x[a-fA-F0-9]{40}\b', page_text)
                    tether_trc20 = re.findall(r'\bT[a-z0-9]{33}\b', page_text)
                    if tether_omni or tether_erc20 or tether_trc20:
                        crypto_wallets['tether'] = tether_omni + tether_erc20 + tether_trc20

                    # Solana
                    solana_addresses = re.findall(r'\b[A-HJ-NP-Za-km-z1-9]{43,44}\b', page_text)
                    if solana_addresses:
                        crypto_wallets['solana'] = solana_addresses

                    # Polkadot
                    polkadot_addresses = re.findall(r'\b[15,2][a-z0-9]{46}\b', page_text)
                    if polkadot_addresses:
                        crypto_wallets['polkadot'] = polkadot_addresses

                    # Chainlink
                    chainlink_addresses = re.findall(r'\b0x[a-fA-F0-9]{40}\b', page_text)
                    if chainlink_addresses:
                        crypto_wallets['chainlink'] = chainlink_addresses

                    # Ethereum Classic
                    etc_addresses = re.findall(r'\b0x[a-fA-F0-9]{40}\b', page_text)
                    if etc_addresses:
                        crypto_wallets['ethereum_classic'] = etc_addresses

                    # Remove duplicates
                    for key in crypto_wallets:
                        crypto_wallets[key] = list(set(crypto_wallets[key]))

                    metadata['crypto_wallets'] = crypto_wallets if crypto_wallets else None

            if fields_to_extract.intersection({'links', 'external_links', 'emails', 'phone_numbers'}):
                # Extract internal and external links if requested
                if 'links' in fields_to_extract or 'external_links' in fields_to_extract:
                    internal_links = []
                    external_links = []
                    base_netloc = urlparse(url).netloc
                    for a in soup.find_all('a', href=True):
                        href = a['href']
                        parsed_href = urlparse(urljoin(url, href))
                        if base_netloc == parsed_href.netloc:
                            internal_links.append(href)
                        else:
                            external_links.append(href)

                    if 'links' in fields_to_extract and internal_links:
                        metadata['links'] = internal_links

                    if 'external_links' in fields_to_extract and external_links:
                        metadata['external_links'] = external_links

                # Extract emails if requested
                if 'emails' in fields_to_extract:
                    emails = set()
                    # Extract emails from the text
                    text_emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', page_text)
                    emails.update(text_emails)

                    # Extract emails from href attributes
                    for a_tag in soup.find_all('a', href=True):
                        href = a_tag['href']
                        if 'mailto:' in href:
                            # Decode the href
                            email = href.split('mailto:')[-1]
                            email = decode_email(email)
                            emails.add(email)

                    # Extract emails from data attributes (handling reversed strings)
                    for span in soup.find_all('span', {'class': 'odEmail'}):
                        user = span.get('data-user', '')
                        website = span.get('data-website', '')
                        if user and website:
                            # Reverse the strings
                            user = user[::-1]
                            website = website[::-1]
                            email = f"{user}@{website}"
                            emails.add(email)

                    metadata['emails'] = list(emails) if emails else None

                # Extract phone numbers if requested
                if 'phone_numbers' in fields_to_extract:
                    phone_numbers = extract_phone_numbers(page_text, default_region=default_region)
                    metadata['phone_numbers'] = phone_numbers if phone_numbers else None

    except requests.exceptions.RequestException as e:
        logging.error(f"Connection error accessing {url}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error accessing {url}: {e}")
        return None

    if metadata:
        logging.info(f"Metadata extracted from {url}")
        return metadata
    else:
        logging.error(f"No metadata extracted from {url}")
        return None


def setup_database(db_path='metadata.db'):
    """
    Sets up a SQLite database to store metadata.

    Args:
        db_path (str): Path to the SQLite database file.

    Returns:
        sqlite3.Connection: SQLite connection object.
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
    Saves extracted metadata to the SQLite database.

    Args:
        conn (sqlite3.Connection): SQLite connection object.
        metadata (dict): Extracted metadata.
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


def can_fetch(session, url, user_agent='*'):
    """
    Checks if the given URL can be fetched according to robots.txt.

    Args:
        session (requests.Session): The session to use for fetching robots.txt.
        url (str): The URL to check.
        user_agent (str): The user agent string.

    Returns:
        bool: True if allowed, False otherwise.
    """
    parsed_url = urlparse(url)
    robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
    rp = robotparser.RobotFileParser()
    try:
        response = session.get(robots_url, timeout=10)
        response.raise_for_status()
        rp.parse(response.text.splitlines())
        can_fetch = rp.can_fetch(user_agent, url)
        if not can_fetch:
            logging.warning(f"Disallowed by robots.txt: {url}")
        return can_fetch
    except requests.exceptions.RequestException as e:
        logging.warning(f"Could not fetch robots.txt for {url}: {e}")
        logging.info(f"No robots.txt found for {url}. Proceeding to scrape.")
        return True  # Proceed if robots.txt cannot be fetched
    except Exception as e:
        logging.warning(f"Unexpected error when fetching robots.txt for {url}: {e}")
        logging.info(f"No robots.txt found for {url}. Proceeding to scrape.")
        return True


def print_human_readable(metadata_list):
    """
    Prints the metadata in a human-readable format with colors, excluding empty fields.

    Args:
        metadata_list (list): List of metadata dictionaries.
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
    Main function to execute the script logic.
    """
    setup_logging()
    parser = setup_argparser()
    global args  # Make args global so it can be accessed in other functions
    args = parser.parse_args()

    # Load URLs
    if args.urls:
        urls = args.urls
    else:
        urls = load_urls_from_file(args.file)

    # Validate and normalize URLs: Remove trailing slashes and validate URLs
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
        fields = [
            'url', 'title', 'description', 'keywords', 'og_title', 'og_description',
            'timestamp', 'headers', 'images', 'scripts', 'css_files',
            'social_links', 'csp', 'server_technologies', 'crypto_wallets',
            'links', 'emails', 'external_links', 'http_headers', 'phone_numbers'
        ]
    elif args.fields:
        fields = args.fields
    else:
        fields = None  # Extract default metadata

    # Check if Tor is required
    tor_required = any(urlparse(url).netloc.endswith('.onion') for url in valid_urls) or args.force_tor

    # Verify Tor is running if needed
    if tor_required and not is_tor_port_open():
        logging.error("Tor SOCKS5 proxy is not accessible. Please ensure Tor is running.")
        sys.exit(1)

    # Setup database
    conn = setup_database(args.database)

    # Collect metadata with concurrency
    results = []
    with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
        future_to_url = {
            executor.submit(
                extract_metadata,
                url,
                args.use_selenium,
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

    # Save results to JSON or output to stdout
    try:
        if args.output == '-':
            # Output to stdout
            json.dump(results, sys.stdout, indent=4)
        else:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=4)
            logging.info(f"Metadata extraction completed. Results saved to '{args.output}'.")
    except Exception as e:
        logging.error(f"Error saving results to '{args.output}': {e}")

    # Output human-readable results if requested
    if args.human_readable:
        print("\nHuman-readable Output:")
        print_human_readable(results)

    # Close the database connection
    conn.close()


if __name__ == "__main__":
    main()
