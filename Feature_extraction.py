#
# This is the definitive, corrected version of: Feature_extraction.py
#
# It is now perfectly aligned with the column names in your provided url_dataset.csv
# This fixes the "not in index" error.
#

from urllib.parse import urlparse
import re
import tldextract

def feature_extract(url):
    """
    Extracts tabular features from a given URL, matching the exact column
    names of your dataset: url_dataset.csv.
    """
    features = {}
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        
        # --- These are the exact features from your url_dataset.csv ---
        features['url_length'] = len(url)
        features['host_length'] = len(parsed.netloc)
        features['path_length'] = len(parsed.path)
        features['query_length'] = len(parsed.query)
        features['num_dots'] = parsed.netloc.count('.')
        features['num_hyphen'] = parsed.netloc.count('-')
        features['is_common_tld'] = 1 if ext.suffix in ['com', 'org', 'net', 'gov', 'edu'] else 0
        features['has_ip'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed.netloc) else 0
        features['is_https'] = 1 if parsed.scheme == 'https' else 0
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        # This is the corrected column name
        features['has_suspicious'] = 1 if any(kw in url.lower() for kw in ['login', 'secure', 'account', 'bank', 'admin', 'update', 'verify']) else 0

    except Exception as e:
        print(f"Error extracting features from URL '{url}': {e}")
        # Return a dictionary of zeros with the correct structure on failure
        keys = ['url_length', 'host_length', 'path_length', 'query_length', 'num_dots', 'num_hyphen', 'is_common_tld', 'has_ip', 'is_https', 'num_digits', 'has_suspicious']
        return {key: 0 for key in keys}
        
    return features