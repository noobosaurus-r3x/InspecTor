**InspecTor** is a command-line tool designed to extract metadata from websites, including **`.onion`** sites, anonymously via the Tor network. It allows users to specify target URLs and retrieve various metadata fields such as emails, phone numbers, links, images, and more. The script supports concurrent requests, saving results to JSON or an SQLite database, and optional use of Selenium for dynamic content.

## **Introduction**

InspecTor is a command-line tool designed to extract metadata from **`.onion`** websites anonymously via the Tor network. It allows users to specify target **`.onion`** URLs and retrieve various metadata fields such as emails, links, images, and more. The script supports concurrent requests, saving results to JSON or an SQLite database, and optional use of Selenium for dynamic content.

## **Features**

- Extract metadata from **`.onion`** websites
- Support for multiple URLs and input files
- Concurrent processing with configurable number of threads
- Optional SSL verification
- Extraction of specific metadata fields
- Optional use of Selenium for dynamic content
- Output to JSON file or stdout
- Save results to SQLite database
- Human-readable output option

## **Requirements**

- **Python 3.x**
- **Tor** installed and running on **`127.0.0.1:9050`**
- **Chrome browser and ChromeDriver** (if using Selenium)

### **Python Packages**

The required Python packages are listed in **`requirements.txt`**:

- **`requests`**
- **`beautifulsoup4`**
- **`selenium`**
- **`fake-useragent`**
- **`colorama`**
- **`urllib3`**
- **`phonenumbers`**


## **Installation**

1. **Clone the repository:**
    
    ```bash
    git clone https://github.com/noobosaurus-r3x/InspecTor.git
    cd InspecTor
    ```
    
2. **Install Python packages:**
    
    ```bash
    pip install -r requirements.txt
    ```
    
3. **Install Tor:**
      
   ```bash
   sudo apt update
   sudo apt install tor
   ```
        
4. **Start Tor service:**
    
    ```bash
    sudo systemctl start tor
    sudo systemctl status tor
    ```
    
5. **Install Chrome and ChromeDriver (if using Selenium):**
    - **Chrome Browser:**
        
        Download and install from the Google Chrome website.
        
    - **ChromeDriver:**
        - Find the version of your Chrome browser:
            
            ```bash
            google-chrome --version
            ```
            
        - Download the corresponding ChromeDriver.
        - Ensure **`chromedriver`** is in your system's PATH or specify the path in the script.


## **Usage**

### **Basic Usage**

Extract metadata from one or more URLs (both `.onion` and regular websites):

```bash
python3 InspecTor.py -u https://exampleonionsite1.onion https://www.example.com
```

Extract metadata from URLs listed in a file:

```bash
python3 InspecTor.py -f urls.txt
```

Force all traffic through Tor:

```bash
python3 InspecTor.py -u https://www.example.com --force-tor
```

### **Command-Line Arguments**

- **`u`**, **`-urls`**
    
    List of **`.onion`** URLs to scrape.
    
- **`f`**, **`-file`**
    
    Path to a file containing **`.onion`** URLs, one per line.
    
- **`o`**, **`-output`**
    
    Output JSON file to save metadata (use **`"-"`** for stdout). Default is **`onion_site_metadata.json`**.
    
- **`-force-tor`**

  Route all traffic through the Tor network, even for regular URLs.

- **`-verify-ssl`**
    
    Enable SSL certificate verification (default: enabled).
    
- **`-no-verify-ssl`**
    
    Disable SSL certificate verification.
    
- **`-use-selenium`**
    
    Use Selenium for handling dynamic content.
    
- **`-max-workers`**
    
    Maximum number of concurrent threads (default: 5).
    
- **`-database`**
    
    SQLite database file to store metadata (default: **`metadata.db`**).
    
- **`-fields`**
    
    Specify which metadata fields to extract. Available fields are listed below.
    
- **`-extract-all`**
    
    Extract all available metadata fields.
    
- **`-human-readable`**, **`hr`**
    
    Output the results in a human-readable format.
    

### **Available Fields**

The following fields can be specified with the **`--fields`** argument:

- **`emails`**
- **`phone_numbers`**
- **`links`**
- **`external_links`**
- **`images`**
- **`scripts`**
- **`css_files`**
- **`social_links`**
- **`csp`**
- **`server_technologies`**
- **`crypto_wallets`**
- **`headers`**
- **`title`**
- **`description`**
- **`keywords`**
- **`og_title`**
- **`og_description`**
- **`timestamp`**
- **`http_headers`**

### **Examples**

**Extract only emails from a `.onion` site:**

```bash
python3 InspecTor.py -u https://example.onion --fields emails -o emails.json
```

**Extract emails and links:**

```bash
python3 InspecTor.py -u https://example.onion --fields emails links -o data.json
```

**Extract all metadata:**

```bash
python3 InspecTor.py -u https://example.onion --extract-all -o all_metadata.json
```

**Extract emails and phone numbers:**

```bash
python3 InspecTor.py -u https://example.com --fields emails phone_numbers -o contact_info.json
```

**Disable SSL verification and use Selenium:**

```bash
python3 InspecTor.py -u https://example.onion -o metadata.json --no-verify-ssl --use-selenium
```

**Output results in a human-readable format:**

```bash
python3 InspecTor.py -u https://example.onion --human-readable
```

**Output JSON to stdout and pipe to `jq` for formatting:**

```bash
python3 InspecTor.py -u https://example.onion -o - | jq '.'
```

## **Output Formats**

- **JSON File:**
    
    By default, the script saves the extracted metadata to **`onion_site_metadata.json`**. Use the **`-o`** argument to specify a different output file or use **`-`** to output to stdout.
    
- **SQLite Database:**
    
    The script saves metadata to an SQLite database (**`metadata.db`** by default). Use the **`--database`** argument to specify a different database file.
    
- **Human-Readable:**
    
    Use the **`--human-readable`** or **`-hr`** flag to print the results in a human-readable format with colored output.
    


## **Notes**

- **Tor Configuration:**
    
    Ensure that the Tor service is running on **`127.0.0.1:9050`**. The script routes all HTTP requests through the Tor SOCKS5 proxy.
    
- **Selenium Usage:**
    
    If the **`--use-selenium`** flag is used, Chrome browser and ChromeDriver must be installed. Selenium is used to handle dynamic content that requires JavaScript execution.
    
- **SSL Verification:**
    
    SSL certificate verification is enabled by default. Some **`.onion`** sites may have invalid certificates. Use the **`--no-verify-ssl`** flag to disable SSL verification.
    
- **Concurrency:**
    
    The script uses multithreading to process multiple URLs concurrently. Adjust the number of workers with the **`--max-workers`** argument as needed.
    
- **Dependencies:**
    
    All Python dependencies are listed in **`requirements.txt`**. Install them using **`pip install -r requirements.txt`**.
    
- **Tor Accessibility:**
    
    If you're scraping **`.onion`** sites or using the **`--force-tor`** option, ensure that the Tor service is accessible and running properly. The script checks if the Tor SOCKS5 proxy is open.
    


## **Contributing**

I am not a professional developer, and this tool could be improved with your help. Feel free to fork the repository and enhance it by adding features, fixing bugs, or optimizing the code. Your contributions are welcome and highly appreciated !


## **License**

This project is licensed under the MIT License.
