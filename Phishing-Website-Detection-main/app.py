import streamlit as st
import numpy as np
import pickle
from urllib.parse import urlparse
import requests
import socket  # Import socket for DNS lookup
import re
from requests.exceptions import RequestException

# Function to get domain from URL
def get_domain(url):  
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
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

# Feature extraction functions
def having_ip(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except:
        return 0

def have_at_sign(url):
    return 1 if "@" in url else 0

def get_length(url):
    return 1 if len(url) >= 54 else 0

def get_depth(url):
    return len([s for s in urlparse(url).path.split('/') if s])

def redirection(url):
    pos = url.rfind('//')
    return 1 if pos > 7 else 0

def http_domain(url):
    return 1 if 'https' in urlparse(url).netloc else 0

def tiny_url(url):
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                          r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                          r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                          r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                          r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                          r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                          r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                          r"tr\.im|link\.zip\.net"
    return 1 if re.search(shortening_services, url) else 0

def prefix_suffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

def web_traffic(url):
    try:
        querystring = {"domain": url}
        headers = {
            "X-RapidAPI-Key": "cd4733fedbmsh6f2cfc21cf195f2p1d088djsn84e6c824c74e",
            "X-RapidAPI-Host": "similar-web.p.rapidapi.com"
        }
        response = requests.get("https://similar-web.p.rapidapi.com/get-analysis", headers=headers, params=querystring)
        data = response.json()
        rank = int(data['GlobalRank']['Rank'])
    except (RequestException, ValueError, KeyError):
        rank = 1

    return 1 if rank < 100000 else 0

def iframe(response):
    if response == "":
        return 1
    return 0 if re.findall(r"[<iframe>|<frameBorder>]", response.text) else 1

def mouse_over(response):
    if response == "":
        return 1
    return 1 if re.findall("<script>.+onmouseover.+</script>", response.text) else 0

def right_click(response):
    if response == "":
        return 1
    return 0 if re.findall(r"event.button ?== ?2", response.text) else 1

def forwarding(response):
    if response == "":
        return 1
    return 1 if len(response.history) > 2 else 0

def get_http_response(url):
    try:
        response = requests.get(url, timeout=5)  # Set a timeout of 5 seconds
        return response
    except RequestException as e:
        st.error(f"Error: {e}")
        return None

def extract_features(url):
    if not is_domain_resolvable(url):
        st.error("The domain does not exist.")
        return []

    features = []
    
    # Address bar based features
    features.append(having_ip(url))
    features.append(have_at_sign(url))
    features.append(get_length(url))
    features.append(get_depth(url))
    features.append(redirection(url))
    features.append(http_domain(url))
    features.append(tiny_url(url))
    features.append(prefix_suffix(url))

    # Domain based features
    dns = 0
    dns_age = 0
    dns_end = 0
    features.extend([dns, dns_age, dns_end])
    
    # Web traffic feature
    features.append(web_traffic(url))
    
    # HTML & Javascript based features
    response = get_http_response(url)
    if response is not None:
        features.append(iframe(response))
        features.append(mouse_over(response))
        features.append(right_click(response))
        features.append(forwarding(response))
    else:
        # If response is None, set these features to 0
        features.extend([0, 0, 0, 0])

    return features

def predict_phishing(features):
    with open('mlp_model.pkl', 'rb') as file:
        loaded_model = pickle.load(file)
    
    new_data = np.array([features])
    prediction = loaded_model.predict(new_data)
    return prediction

def main():
    st.title('Phishing Detection System')
    st.write("Enter a URL to check if it's phishing or not.")
    
    # Input URL
    url = st.text_input("Enter URL:")
    
    if st.button("Check"):
        # Extract features
        st.write("Extracting features...")
        features = extract_features(url)
        
        # Make prediction
        if features:
            st.write("Predicting...")
            prediction = predict_phishing(features)
            
            # Display prediction
            if prediction[0] == 0:
                st.write("Prediction made:")
                st.error("Phishing Alert! This URL is classified as phishing.")
            else:
                st.write("Prediction made:")
                st.success("Shows no signs of malicious activity. Nevertheless, remain vigilant while browsing")
    
if __name__ == '__main__':
    main()
