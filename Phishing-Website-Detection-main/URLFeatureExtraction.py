# -*- coding: utf-8 -*-

# importing required packages for this section
from urllib.parse import urlparse
import ipaddress
import re
import socket  # Import socket for DNS lookup
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import whois


#Function to confirm if the URL is valid
def is_valid_url(url):
    """
    Validates if the provided URL is in a valid format.
    
    Parameters:
    - url: string, the URL to be validated
    
    Returns:
    - bool: True if the URL is valid, False otherwise
    """
    # Regular expression for validating a URL (ensuring it has a scheme and a domain)
    url_pattern = re.compile(
        r'^(https?:\/\/)'  # scheme (http or https)
        r'([a-zA-Z0-9.-]+)'  # domain
        r'(\.[a-zA-Z]{2,})'  # top-level domain
        r'(\/[^\s]*)?$'      # optional path
    )
    
    return re.match(url_pattern, url) is not None


def featureExtraction(url, label):
    """
    Extract features from the given URL and return them as a list.
    
    Parameters:
    - url: string, the URL to be processed
    - label: int, the label for the URL (0 = legitimate, 1 = phishing)
    
    Returns:
    - list: extracted features for the URL, or an indication of an invalid URL
    """
    # Validate the URL
    if not is_valid_url(url):
        # Handle invalid URLs (you can choose how to handle this, e.g., skip or flag)
        print(f"Invalid URL: {url}")
        return None  # Or return a list of default values
    
    # Proceed with feature extraction if the URL is valid
    features = []

    # Example feature extraction logic (replace with your actual logic)
    # Extract features here...

    # Add label to the features
    features.append(label)
    
    return features

# Function to get domain from URL
def get_domain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www\.", domain):
        domain = domain.replace("www.", "")
    return domain

# Function to check if domain resolves
def is_domain_resolvable(url):
    domain = get_domain(url)
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False

# IP Address in URL
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip

# Presence of "@" in URL
def haveAtSign(url):
    if "@" in url:
        at = 1    
    else:
        at = 0    
    return at

# Length of URL
def getLength(url):
    if len(url) < 54:
        length = 0            
    else:
        length = 1            
    return length

# Depth of URL
def getDepth(url):
    s = urlparse(url).path.split('/')
    depth = 0
    for j in range(len(s)):
        if len(s[j]) != 0:
            depth = depth + 1
    return depth

# Redirection "//" in URL
def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        if pos > 7:
            return 1
        else:
            return 0
    else:
        return 0

# "http/https" in Domain name
def httpDomain(url):
    domain = urlparse(url).netloc
    if 'https' in domain:
        return 1
    else:
        return 0

# URL Shortening Services “TinyURL”
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

def tinyURL(url):
    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return 0

# Prefix or Suffix "-" in Domain
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1
    else:
        return 0

# Web Traffic
def web_traffic(url):
    try:
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
            "REACH")['RANK']
        rank = int(rank)
    except TypeError:
        return 1
    if rank < 100000:
        return 1
    else:
        return 0

# Age of Domain
def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date
    if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1
    if ((expiration_date is None) or (creation_date is None)):
        return 1
    elif ((type(expiration_date) is list) or (type(creation_date) is list)):
        return 1
    else:
        ageofdomain = abs((expiration_date - creation_date).days)
        if ((ageofdomain / 30) < 6):
            age = 1
        else:
            age = 0
    return age

# End Period of Domain
def domainEnd(domain_name):
    expiration_date = domain_name.expiration_date
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1
    if (expiration_date is None):
        return 1
    elif (type(expiration_date) is list):
        return 1
    else:
        today = datetime.now()
        end = abs((expiration_date - today).days)
        if ((end / 30) < 6):
            end = 0
        else:
            end = 1
    return end

# IFrame Redirection
def iframe(response):
    if response == "":
        return 1
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1

# Mouse Over
def mouseOver(response):
    if response == "":
        return 1
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return 0

# Disabling Right Click
def rightClick(response):
    if response == "":
        return 1
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        else:
            return 1

# Website Forwarding
def forwarding(response):
    if response == "":
        return 1
    else:
        if len(response.history) <= 2:
            return 0
        else:
            return 1

# Function to extract features
def featureExtraction(url):
    if not is_domain_resolvable(url):
        return [None] * 17  # Returning None for each feature if the domain is not resolvable

    features = []
    
    # Address bar based features (10)
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))
    
    # Domain based features (4)
    dns = 0
    try:
        domain_name = whois.whois(get_domain(url))
    except:
        dns = 1

    features.append(dns)
    features.append(web_traffic(url))
    features.append(1 if dns == 1 else domainAge(domain_name))
    features.append(1 if dns == 1 else domainEnd(domain_name))
    
    # HTML & JavaScript based features
    try:
        response = requests.get(url)
    except:
        response = ""

    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))
    
    return features

# Converting the list to dataframe
feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
                      'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                      'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over','Right_Click', 'Web_Forwards', 'Label']
