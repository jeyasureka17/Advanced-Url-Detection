#
# This is the definitive, corrected version of: url_analyzer.py
#
# FIX: Implements a robust retry mechanism for the VirusTotal API call to handle
#      temporary network failures or API issues.
# FIX: Refines the scoring logic in the other analysis functions.
#

import re
import whois
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime
import time

# In url_analyzer.py
# --- VirusTotal API Configuration ---
from config import VIRUSTOTAL_API_KEY
VT_URL_REPORT_ENDPOINT = 'https://www.virustotal.com/vtapi/v2/url/report'

def analyze_url_with_virustotal(url, retries=2, delay=5):
    """
    Gets a scan report for a URL from VirusTotal, with a built-in retry mechanism.
    """
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
    for attempt in range(retries):
        try:
            response = requests.get(VT_URL_REPORT_ENDPOINT, params=params, timeout=20)
            if response.status_code == 204: # Rate limit exceeded
                print(f"VirusTotal rate limit exceeded. Retrying in {delay}s...")
                time.sleep(delay)
                continue # Go to the next attempt
            
            response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
            
            result = response.json()
            if result.get('response_code') == 1:
                return f"{result.get('positives', 0)} / {result.get('total', 0)}"
            else:
                return "Not Found in VT"
        except requests.RequestException as e:
            print(f"VirusTotal request failed (attempt {attempt+1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(delay)
            else:
                return "Network Error"
    return "API Error" # Should only be reached if all retries fail


def extract_lexical_features(url):
    try:
        if not re.match(r'^(http|https|ftp)://', url): url = 'http://' + url
        parsed = urlparse(url); hostname = parsed.netloc
        return { 'url_length': len(url), 'hostname_length': len(hostname), 'path_length': len(parsed.path), 'num_dots': hostname.count('.'), 'num_hyphens': hostname.count('-'), 'num_at': url.count('@'), 'num_query_params': len(parsed.query.split('&')) if parsed.query else 0, 'num_digits': sum(c.isdigit() for c in url), 'has_ip': 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0, 'has_https': 1 if parsed.scheme == 'https' else 0, 'has_suspicious_keyword': 1 if any(kw in url.lower() for kw in ['login','secure','account','bank','admin','update','verify','signin','password']) else 0 }
    except: return {k:0 for k in ['url_length','hostname_length','path_length','num_dots','num_hyphens','num_at','num_query_params','num_digits','has_ip','has_https','has_suspicious_keyword']}

def analyze_host_features(url):
    results = {'score': 0, 'reasons': []}
    try:
        hostname = urlparse(url).hostname
        if hostname is None: return results
        try:
            domain_info = whois.whois(hostname)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
                age = (datetime.now() - creation_date).days
                if age < 90: results['reasons'].append(f"- Domain is very new ({age} days old)."); results['score'] += 3
        except: results['reasons'].append("- Domain registration info (WHOIS) is private or unavailable."); results['score'] += 1
    except: pass
    return results

def analyze_content_features(url):
    results = {'score': 0, 'reasons': []}
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    try:
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        if len(soup.find_all('iframe')) > 0: results['reasons'].append("- Page uses hidden iFrames."); results['score'] += 2
        for form in soup.find_all('form'):
            action = form.get('action', '')
            if not action or (urlparse(action).hostname and urlparse(action).hostname != urlparse(url).hostname):
                results['reasons'].append("- Contains forms that may submit data to another domain."); results['score'] += 4
                break
    except Exception as e:
        print(f"Content analysis failed: {e}")
    return results