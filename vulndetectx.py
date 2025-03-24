import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import concurrent.futures

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

def scan_sql_injection(url):
    payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url)
        if "error" in response.text.lower() or "syntax" in response.text.lower():
            return f"{RED}SQL Injection vulnerability found at {url}{RESET}"
    return None

def scan_xss(url):
    payload = "<script>alert('XSS')</script>"
    response = requests.get(url, params={"q": payload})
    if payload in response.text:
        return f"{RED}XSS vulnerability found at {url}{RESET}"
    return None

def scan_headers(url):
    insecure_headers = []
    response = requests.get(url)
    headers = response.headers
    if "Content-Security-Policy" not in headers:
        insecure_headers.append("Missing Content-Security-Policy")
    if "X-Frame-Options" not in headers:
        insecure_headers.append("Missing X-Frame-Options")
    if insecure_headers:
        return f"{RED}Insecure headers at {url}: {', '.join(insecure_headers)}{RESET}"
    return None

def scan_page(url):
    results = []
    sql_result = scan_sql_injection(url)
    if sql_result:
        results.append(sql_result)
    xss_result = scan_xss(url)
    if xss_result:
        results.append(xss_result)
    header_result = scan_headers(url)
    if header_result:
        results.append(header_result)
    return results

def crawl_and_scan(base_url):
    visited = set()
    to_visit = [base_url]
    with concurrent.futures.ThreadPoolExecutor() as executor:
        while to_visit:
            url = to_visit.pop()
            if url in visited:
                continue
            visited.add(url)
            print(f"{GREEN}Scanning: {url}{RESET}")
            results = scan_page(url)
            for result in results:
                print(result)
            try:
                response = requests.get(url)
                soup = BeautifulSoup(response.text, "html.parser")
                for link in soup.find_all("a", href=True):
                    full_url = urljoin(base_url, link["href"])
                    if base_url in full_url and full_url not in visited:
                        to_visit.append(full_url)
            except Exception as e:
                print(f"{RED}Error crawling {url}: {e}{RESET}")

if __name__ == "__main__":
    target_url = input("Enter target URL: ")
    crawl_and_scan(target_url)