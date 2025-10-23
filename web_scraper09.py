import mysql.connector
import requests
from flask import Flask, render_template, request, jsonify
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import re
import tldextract
import whois
import os
from datetime import datetime
import ssl
import socket
import json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import google.generativeai as genai
from dotenv import load_dotenv
from waitress import serve

load_dotenv(dotenv_path="credentials.env")

db_port_env = os.getenv("DB_PORT")
if not db_port_env:
    raise ValueError("FATAL ERROR: DB_PORT environment variable is not set or is empty.")

try:
    db_port_int = int(db_port_env)
except ValueError:
    raise ValueError(f"FATAL ERROR: Invalid DB_PORT '{db_port_env}'. Port must be a number.")

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": db_port_int,  
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
    "ssl_ca": os.getenv("DB_SSL_CA", "ca.pem")
}

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

try:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel("gemini-flash-latest")
    print("Gemini API configured successfully.")
except Exception as e:
    gemini_model = None
    print(f"Warning: Gemini API configuration failed. Falling back to local analysis. Error: {e}")

app = Flask(__name__, template_folder="web_design")

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Content-Security-Policy'
]

def is_suspicious(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    reasons = []
    extracted = tldextract.extract(url)
    subdomain, root_domain, suffix = extracted.subdomain.lower(), extracted.domain.lower(), extracted.suffix.lower()

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", domain):
        reasons.append("Uses IP address instead of domain name")
    if "@" in url:
        reasons.append("Contains '@' symbol (credential embedding attempt)")
    if domain.count('-') > 4:
        reasons.append("Excessive hyphens in domain")
    suspicious_tlds = [".xyz", ".top", ".zip", ".review", ".club", ".loan", ".win"]
    if any(suffix.endswith(tld.strip(".")) for tld in suspicious_tlds):
        reasons.append(f"Suspicious TLD: {suffix}")
    if len(root_domain) > 25:
        reasons.append("Excessively long domain name")
    if subdomain.count('.') >= 3:
        reasons.append("Too many subdomains (potential deception)")
    suspicious_keywords = ['login', 'secure', 'account', 'verify', 'banking', 'paypal', 'bantuan', 'malaysia', 'subsidi', 'claim']
    if any(keyword in root_domain or keyword in subdomain for keyword in suspicious_keywords):
        reasons.append("Contains sensitive/trigger keywords in domain")
    if root_domain == "agronet-my" and ("bantuan" in subdomain or "malaysia" in subdomain):
        reasons.append("Suspicious subdomain usage with agronet-my (known scam pattern)")
    return len(reasons) > 0, reasons if reasons else ["Looks normal"]

def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        return (datetime.now() - creation_date).days if creation_date else None
    except Exception as e:
        print(f"Domain age check failed for {domain}: {e}")
        return None

def check_ssl_certificate(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme != 'https': return False
        hostname = parsed.netloc.split(':')[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return (expires - datetime.now()).days > 7
    except Exception as e:
        print(f"SSL check failed for {url}: {e}")
        return False

def analyze_website_local(url, timeout=10):
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    session.headers.update({'User-Agent': 'Mozilla/5.0'})

    try:
        response = session.get(url, timeout=timeout, verify=True, allow_redirects=True)
        status = response.status_code
        threat_score, warnings = 0, []

        is_sus, reasons = is_suspicious(url)
        if is_sus:
            threat_score += 30
            warnings.extend(reasons)

        domain_age = get_domain_age(urlparse(url).netloc)
        if domain_age is not None and domain_age < 30:
            threat_score += 20
            warnings.append(f"New domain ({domain_age} days old)")
        elif domain_age is None:
            warnings.append("Could not determine domain age")

        if url.startswith('https://') and not check_ssl_certificate(url):
            threat_score += 25
            warnings.append("Invalid or expiring SSL certificate")
        elif not url.startswith('https://'):
            threat_score += 15
            warnings.append("No HTTPS (insecure connection)")

        missing_headers = [h for h in SECURITY_HEADERS if h not in response.headers]
        if missing_headers:
            threat_score += len(missing_headers) * 5
            warnings.append(f"Missing security headers: {', '.join(missing_headers)}")

        soup = BeautifulSoup(response.text, "html.parser")
        if len(soup.find_all(style=re.compile(r'display:\s*none|visibility:\s*hidden', re.I))) > 10:
            threat_score += 15
            warnings.append("Excessive hidden elements detected")
        if len(soup.find_all('iframe')) > 5:
            threat_score += 10
            warnings.append("Multiple iframes detected")

        flag = "malicious" if threat_score >= 60 else "suspicious" if threat_score >= 30 else "legitimate"
        return {
            "url": url,
            "status": status,
            "threat_score": threat_score,
            "flag": flag,
            "warnings": warnings,
            "domain_age_days": domain_age,
            "analysis_source": "local"
        }
    except Exception as e:
        return {
            "url": url,
            "status": "error",
            "flag": "suspicious",
            "warnings": [f"Local analysis failed: {str(e)}"],
            "threat_score": 30,
            "analysis_source": "local"
        }

def analyze_with_gemini(url):
    if not gemini_model:
        return {"error": "Gemini model not initialized"}
    prompt = f"""
    Analyze the following URL for potential phishing, malware, or scamming threats: {url}

    Evaluate it based on:
    - Domain reputation and age.
    - HTTPS and SSL certificate validity.
    - URL structure.
    - Suspicious TLDs.
    - Scam-related keywords.

    Respond in raw JSON:
    {{
      "url": "{url}",
      "threat_score": <0-100>,
      "flag": "legitimate" | "suspicious" | "malicious",
      "warnings": [...]
    }}
    """
    try:
        response = gemini_model.generate_content(prompt)
        cleaned = response.text.strip().replace("```json", "").replace("```", "")
        result = json.loads(cleaned)
        result["analysis_source"] = "gemini"
        return result
    except Exception as e:
        print(f"Gemini API call failed: {e}")
        return {"error": str(e), "analysis_source": "gemini"}

def analyze_news_with_gemini(text_content):
    if not gemini_model:
        return {"error": "Gemini model not initialized"}

    prompt = f"""
    Analyze the following news article text for fake news and political/national bias.
    Provide a fake news score from 0 (completely true) to 100 (completely false).
    Determine the political or national bias. This could be ideological (e.g., "Nationalist", "State-Sponsored Propaganda", "Libertarian"), national (e.g., "Pro-Russia", "Pro-China", "Pro-Western"), or related to a specific political stance (e.g., "Left-Leaning", "Right-Leaning"). If no significant bias is detected, label it as "Center" or "Neutral".
    Provide a brief summary of your reasoning for both the score and the bias, explaining which elements of the text led to your conclusion.

    Article text: "{text_content}"

    Respond in raw JSON format only. Do not include any other text or markdown.
    {{
        "fake_news_score": <0-100>,
        "political_bias": "<A descriptive bias label>",
        "reasoning": "..."
    }}
    """
    try:
        response = gemini_model.generate_content(prompt)
        cleaned = response.text.strip().replace("```json", "").replace("```", "")
        result = json.loads(cleaned)
        result["analysis_source"] = "gemini"
        return result
    except Exception as e:
        print(f"Gemini API call for news analysis failed: {e}")
        return {"error": str(e), "analysis_source": "gemini"}


def save_to_db(result):
    conn = None
    cursor = None
    try:
        print(f"DEBUG: Raw dictionary received by save_to_db: {result}")

        score_raw = result.get("threat_score")
        threat_score_val = None  
        if score_raw is not None:
            try:
                threat_score_val = int(float(score_raw))
            except (ValueError, TypeError):
                print(f"Warning: Could not convert threat_score '{score_raw}' to int. Storing as NULL.")
                threat_score_val = None 

        age_raw = result.get("domain_age_days")
        domain_age_val = None 
        if age_raw is not None:
            try:
                domain_age_val = int(float(age_raw))
            except (ValueError, TypeError):
                print(f"Warning: Could not convert domain_age '{age_raw}' to int. Storing as NULL.")
                domain_age_val = None

        values_to_insert = (
            result.get("url", "URL Missing"),
            str(result.get("status", "N/A")),
            threat_score_val,
            result.get("flag", "unknown"),
            json.dumps(result.get("warnings", [])),
            domain_age_val,
            result.get("analysis_source", "unknown"),
        )

        print(f"DEBUG: Final, sanitized values being sent to database: {values_to_insert}")

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS site_analysis (
                id INT AUTO_INCREMENT PRIMARY KEY, url TEXT NOT NULL, status VARCHAR(20),
                threat_score INT, flag VARCHAR(20), warnings JSON, domain_age_days INT,
                analysis_source VARCHAR(20), analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_flag (flag), INDEX idx_timestamp (analysis_timestamp)
            )
        """)

        insert_query = """
        INSERT INTO site_analysis 
        (url, status, threat_score, flag, warnings, domain_age_days, analysis_source)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        
        cursor.execute(insert_query, values_to_insert)
        conn.commit()
        print("SUCCESS: Data has been saved to the database.")

    except mysql.connector.Error as err:
        print(f"DATABASE CONNECTOR ERROR: {err}")
    except Exception as err:
        print(f"UNEXPECTED GENERIC ERROR in save_to_db: {err}")
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

def save_news_analysis_to_db(result):
    conn = None
    cursor = None
    try:
        print(f"DEBUG: Raw dictionary received by save_news_analysis_to_db: {result}")

        score_raw = result.get("fake_news_score")
        fake_news_score_val = None
        if score_raw is not None:
            try:
                fake_news_score_val = int(float(score_raw))
            except (ValueError, TypeError):
                print(f"Warning: Could not convert fake_news_score '{score_raw}' to int. Storing as NULL.")
                fake_news_score_val = None

        values_to_insert = (
            result.get("original_text", "Original text missing"),
            fake_news_score_val,
            result.get("political_bias", "unknown"),
            result.get("reasoning", ""),
            result.get("analysis_source", "unknown"),
        )

        print(f"DEBUG: Final, sanitized values being sent to database for news analysis: {values_to_insert}")

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fake_news_analysis (
                id INT AUTO_INCREMENT PRIMARY KEY,
                original_text TEXT NOT NULL,
                fake_news_score INT,
                political_bias VARCHAR(50),
                reasoning TEXT,
                analysis_source VARCHAR(20),
                analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        insert_query = """
        INSERT INTO fake_news_analysis
        (original_text, fake_news_score, political_bias, reasoning, analysis_source)
        VALUES (%s, %s, %s, %s, %s)
        """
        
        cursor.execute(insert_query, values_to_insert)
        conn.commit()
        print("SUCCESS: News analysis data has been saved to the database.")

    except mysql.connector.Error as err:
        print(f"DATABASE CONNECTOR ERROR: {err}")
    except Exception as err:
        print(f"UNEXPECTED GENERIC ERROR in save_news_analysis_to_db: {err}")
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


def validate_url(url):
    if not url: return False, "URL cannot be empty"
    if not url.startswith(('http://', 'https://')): url = 'https://' + url
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]): return False, "Invalid URL format"
        if len(url) > 500: return False, "URL is too long"
        return True, url
    except Exception:
        return False, "Invalid URL"

@app.route("/")
def home():
    return render_template("layout.html")

@app.route("/analyze", methods=["POST"])
@limiter.limit("10 per minute")
def analyze_api():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "No URL provided"}), 400

    is_valid, url_or_error = validate_url(data["url"].strip())
    if not is_valid:
        return jsonify({"error": url_or_error}), 400
    validated_url = url_or_error
    print("Running local analysis to gather factual data...")
    local_data = analyze_website_local(validated_url)
    if gemini_model:
        print("Attempting analysis with Gemini API...")
        gemini_result = analyze_with_gemini(validated_url)

        if gemini_result and "error" not in gemini_result:
            print("Merging local facts with Gemini analysis...")
            final_result = gemini_result
            final_result['domain_age_days'] = local_data.get('domain_age_days') 
            final_result['status'] = local_data.get('status') 
            
        else:
            print("Gemini failed. Using local analysis result.")
            final_result = local_data
    else:
        print("Gemini not configured. Using local analysis result.")
        final_result = local_data

    if final_result and "error" not in final_result:
        save_to_db(final_result)

    return jsonify(final_result)

@app.route("/analyze-news", methods=["POST"])
@limiter.limit("10 per minute")
def analyze_news_api():
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400

    text_content = data["text"].strip()
    if not text_content:
        return jsonify({"error": "Text content cannot be empty"}), 400

    if gemini_model:
        print("Attempting news analysis with Gemini API...")
        analysis_result = analyze_news_with_gemini(text_content)

        if "error" not in analysis_result:
            analysis_result["original_text"] = text_content
            save_news_analysis_to_db(analysis_result)
        
        return jsonify(analysis_result)
    else:
        return jsonify({"error": "Gemini model not configured for news analysis."}), 500

if __name__ == "__main__":
    is_production = os.getenv('RENDER', False)
    port = int(os.getenv('PORT', 5000))

    if is_production:
        print(f"INFO: Running production server on port {port}...")
        serve(app, host='0.0.0.0', port=port)
    else:
        print("INFO: Running development server...")
        app.run(debug=True, host='0.0.0.0', port=port)