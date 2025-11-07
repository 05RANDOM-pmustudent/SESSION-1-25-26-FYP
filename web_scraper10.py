import mysql.connector
import requests
from flask import Flask, render_template, request, jsonify, g, make_response, session, redirect, url_for, flash
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import re
import tldextract
import whois
import os
import time
from datetime import datetime, timedelta
import random
import ssl
import socket
import json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import google.generativeai as genai
from dotenv import load_dotenv
from waitress import serve
import PIL.Image
import feedparser
from flask import send_from_directory
import uuid
from functools import wraps
import hashlib


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
    gemini_vision_model = genai.GenerativeModel("gemini-2.5-pro")
    print("Gemini API configured successfully for text and vision models.")
except Exception as e:
    gemini_model = None
    gemini_vision_model = None
    print(f"Warning: Gemini API configuration failed. Falling back to local analysis. Error: {e}")

app = Flask(__name__, template_folder="web_design")
app.secret_key = os.urandom(24)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

# --- NEW CACHE CONTROL DECORATOR ---
def nocache(view):
    """Decorator to ensure a view is not cached by the browser."""
    @wraps(view)
    def no_cache_impl(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return no_cache_impl

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Content-Security-Policy'
]

def get_db():
    if 'db' not in g:
        g.db = mysql.connector.connect(**DB_CONFIG)
    return g.db

@app.teardown_appcontext
def teardown_db(exception):
    db = g.pop('db', None)
    if db is not None and db.is_connected():
        db.close()
        print("INFO: Database connection closed.")

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS site_analysis (
                id INT AUTO_INCREMENT PRIMARY KEY, url TEXT NOT NULL, status VARCHAR(20),
                threat_score INT, flag VARCHAR(20), warnings JSON, domain_age_days INT,
                analysis_source VARCHAR(20), analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                share_id VARCHAR(36) UNIQUE,
                INDEX idx_flag (flag), INDEX idx_timestamp (analysis_timestamp)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fake_news_analysis (
                id INT AUTO_INCREMENT PRIMARY KEY, original_text TEXT NOT NULL, fake_news_score INT,
                political_bias VARCHAR(50), reasoning TEXT, analysis_source VARCHAR(20),
                analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS screenshot_analysis (
                id INT AUTO_INCREMENT PRIMARY KEY, filename VARCHAR(255), threat_score INT,
                flag VARCHAR(20), warnings JSON, analysis_source VARCHAR(20),
                analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_feedback (
                id INT AUTO_INCREMENT PRIMARY KEY, url VARCHAR(512), is_accurate BOOLEAN,
                reason VARCHAR(255), other_text TEXT,
                feedback_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, INDEX(url)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fake_news_feedback (
            id INT AUTO_INCREMENT PRIMARY KEY,
            original_text_hash VARCHAR(64) NOT NULL,
            is_accurate BOOLEAN,
            reason VARCHAR(255),
            other_text TEXT,
            feedback_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX(original_text_hash)
        )
    """)
        
        db.commit()
        cursor.close()
        print("INFO: Database schema verified successfully.")

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
    suspicious_tlds = [".xyz", ".top", ".zip", ".review"]
    if any(suffix.endswith(tld.strip(".")) for tld in suspicious_tlds):
        reasons.append(f"Suspicious TLD: {suffix}")
    if len(root_domain) > 25:
        reasons.append("Excessively long domain name")
    if subdomain.count('.') >= 3:
        reasons.append("Too many subdomains (potential deception)")
    suspicious_keywords = ['login', 'secure', 'verify', 'banking', 'bantuan', 'subsidi']
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
        # --- THE SSL CRASH FIX ---
        response = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
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
        return { "url": url, "status": status, "threat_score": threat_score, "flag": flag, "warnings": warnings, "domain_age_days": domain_age, "analysis_source": "local" }
    except Exception as e:
        return { "url": url, "status": "error", "flag": "suspicious", "warnings": [f"Local analysis failed: {str(e)}"], "threat_score": 30, "analysis_source": "local", "error": f"Local analysis failed: {str(e)}" }

def analyze_with_gemini(url):
    if not gemini_model:
        return {"error": "Gemini model not initialized"}
    prompt = f"""
    Analyze the following URL for potential phishing, malware, or scamming threats: {url}
    Evaluate it based on:
    - Domain reputation and age. - HTTPS and SSL certificate validity. - URL structure.
    - Suspicious TLDs. - Scam-related keywords.
    Respond in raw JSON: {{ "url": "{url}", "threat_score": <0-100>, "flag": "legitimate" | "suspicious" | "malicious", "warnings": [...] }}
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
    Determine the political or national bias. E.g., "Nationalist", "State-Sponsored Propaganda", "Left-Leaning", "Right-Leaning", "Pro-Western". If neutral, label it as "Center" or "Neutral".
    Provide a brief summary of your reasoning.
    Article text: "{text_content}"
    Respond in raw JSON format only. Do not include markdown.
    {{ "fake_news_score": <0-100>, "political_bias": "<A descriptive bias label>", "reasoning": "..." }}
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

def analyze_screenshot_with_gemini(image_file_stream, filename):
    if not gemini_vision_model:
        return {"error": "Gemini vision model is not available."}

    prompt_text = """Analyze this screenshot for any signs of a scam or phishing attempt. Look for suspicious URLs, logos of banks or services used incorrectly, urgent language, grammatical errors, or requests for personal information. Respond in raw JSON with keys "threat_score" (0-100), "flag" ("legitimate", "suspicious", "malicious"), and "warnings" (a list of objects with "title" and "explanation")."""
    
    try:
        img = PIL.Image.open(image_file_stream)
        response = gemini_vision_model.generate_content([prompt_text, img])
        cleaned = response.text.strip().replace("```json", "").replace("```", "")
        result = json.loads(cleaned)
        result["analysis_source"] = "gemini_vision"
        result["filename"] = filename
        return result
    except Exception as e:
        print(f"Gemini Vision API call failed: {e}")
        return {"error": str(e), "analysis_source": "gemini_vision"}

def save_to_db(result):
    """
    Saves analysis result to the database.
    Returns a tuple: (success_boolean, error_message_string_or_None)
    """
    conn = None
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        insert_query = """
            INSERT INTO site_analysis 
            (url, status, threat_score, flag, warnings, domain_age_days, analysis_source, share_id) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        values_to_insert = (
            result.get("url"),
            str(result.get("status", "N/A")),
            int(result.get("threat_score", 0)),
            result.get("flag"),
            json.dumps(result.get("warnings", [])),
            result.get("domain_age_days"),
            result.get("analysis_source"),
            result.get("share_id")
        )
        cursor.execute(insert_query, values_to_insert)
        conn.commit()
        return True, None # Success
    except mysql.connector.Error as err:
        # This is the crucial change: we catch the specific database error and return it.
        print(f"DATABASE ERROR in save_to_db: {err}")
        return False, str(err) # Failure
    except Exception as err:
        # Catch any other unexpected errors
        print(f"UNEXPECTED ERROR in save_to_db: {err}")
        return False, str(err) # Failure
    finally:
        if cursor: cursor.close()

def save_news_analysis_to_db(result):
    conn = None
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        insert_query = """
            INSERT INTO fake_news_analysis 
            (original_text, fake_news_score, political_bias, reasoning, analysis_source) 
            VALUES (%s, %s, %s, %s, %s)
        """
        values_to_insert = (
            result.get("original_text"),
            int(result.get("fake_news_score", 0)),
            result.get("political_bias"),
            result.get("reasoning"),
            result.get("analysis_source")
        )
        cursor.execute(insert_query, values_to_insert)
        conn.commit()
    except Exception as err:
        print(f"DATABASE ERROR in save_news_analysis_to_db: {err}")
    finally:
        if cursor: cursor.close()

def save_screenshot_analysis_to_db(result):
    conn = None
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        insert_query = """
            INSERT INTO screenshot_analysis 
            (filename, threat_score, flag, warnings, analysis_source) 
            VALUES (%s, %s, %s, %s, %s)
        """
        values_to_insert = (
            result.get("filename"),
            int(result.get("threat_score", 0)),
            result.get("flag"),
            json.dumps(result.get("warnings", [])),
            result.get("analysis_source")
        )
        cursor.execute(insert_query, values_to_insert)
        conn.commit()
    except Exception as err:
        print(f"DATABASE ERROR in save_screenshot_analysis_to_db: {err}")
    finally:
        if cursor: cursor.close()

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
        
NEWS_CACHE = {"timestamp": 0, "data": []}
CACHE_DURATION_SECONDS = 3600  

PLACEHOLDER_IMAGES = [
    "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?q=80&w=2070&auto=format&fit=crop",
    "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?q=80&w=2070&auto=format&fit=crop",
    "https://images.unsplash.com/photo-1614064548237-096537d5464f?q=80&w=1974&auto=format&fit=crop",
    "https://images.unsplash.com/photo-1544890225-2fde0e66ea0b?q=80&w=1974&auto=format&fit=crop"
]

NEWS_FEEDS = {
    "The Hacker News": "http://feeds.feedburner.com/TheHackersNews",
    "Dark Reading": "http://www.darkreading.com/rss/all.xml",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Threatpost": "https://threatpost.com/feed/"
}

def get_og_image(url):
    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        og_image = soup.find('meta', property='og:image')
        if og_image and og_image.get('content'):
            return og_image['content']
    except Exception as e:
        print(f"Could not fetch image for {url}: {e}")
    return None

def fetch_tech_security_news():
    global NEWS_CACHE
    current_time = time.time()

    if current_time - NEWS_CACHE["timestamp"] < CACHE_DURATION_SECONDS:
        return NEWS_CACHE["data"]

    news_items = []
    
    for source, url in NEWS_FEEDS.items():
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:3]:  
                image_url = get_og_image(entry.link) or random.choice(PLACEHOLDER_IMAGES)
                news_items.append({
                    "title": entry.title,
                    "link": entry.link,
                    "source": source,
                    "image": image_url
                })
        except Exception as e:
            print(f"Error fetching news from {source}: {e}")
    
    random.shuffle(news_items) 
    NEWS_CACHE["timestamp"] = current_time
    NEWS_CACHE["data"] = news_items
    return news_items

# --- START: SUPER-SIMPLE AUTHENTICATION ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('You must be logged in to view this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Check credentials from .env file
        if request.form['username'] == os.getenv('ADMIN_USERNAME') and \
           request.form['password'] == os.getenv('ADMIN_PASSWORD'):
            session['logged_in'] = True
            return redirect(url_for('admin_page'))
        else:
            flash('Invalid credentials. Please try again.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You have been logged out.')
    return redirect(url_for('home'))

# --- END: SUPER-SIMPLE AUTHENTICATION ---

@app.route("/")
def home():
    return render_template("layoutRE.html")

@app.route('/tech_security_news.html')
def tech_security_news():
    return send_from_directory('web_design', 'tech_security_news.html')

@app.route("/api/tech-security-news")
@nocache
def get_tech_security_news():
    news_items = fetch_tech_security_news()
    return render_template("tech_security_news.html", news_items=news_items)

@app.route("/admin")
@login_required
def admin_page():
    return render_template("admin.html")

@app.route("/analysis/<share_id>")
def view_analysis(share_id):
    conn = None
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM site_analysis WHERE share_id = %s", (share_id,))
        analysis_data = cursor.fetchone()
        
        if analysis_data and 'warnings' in analysis_data:
            analysis_data['warnings'] = json.loads(analysis_data['warnings'])
            
    except Exception as e:
        print(f"Error fetching analysis for share_id {share_id}: {e}")
        return "Error loading analysis result.", 500
    finally:
        if cursor: cursor.close()

    if analysis_data:
        return render_template("view_analysis.html", result=analysis_data)
    else:
        return "Analysis not found.", 404

@app.route("/analyze", methods=["POST"])
def analyze_api():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "No URL provided"}), 400
   
    is_valid, url_or_error = validate_url(data["url"].strip())
    if not is_valid:
        return jsonify({"error": url_or_error}), 400
   
    validated_url = url_or_error
   
    try:
        # --- Perform the analysis as before ---
        local_data = analyze_website_local(validated_url)
        if "error" in local_data:
            return jsonify(local_data), 500
        if gemini_model:
            gemini_result = analyze_with_gemini(validated_url)
            if "error" not in gemini_result:
                final_result = gemini_result
                final_result['domain_age_days'] = local_data.get('domain_age_days')
                final_result['status'] = local_data.get('status')
            else:
                final_result = local_data
        else:
            final_result = local_data
       
        share_id = str(uuid.uuid4())
        final_result["share_id"] = share_id
        # --- This is the crucial change: Check if the save was successful ---
        success, error_message = save_to_db(final_result)
       
        if not success:
            # If it failed, return a 500 server error with the database message.
            return jsonify({
                "error": "Analysis completed, but failed to save result to the database.",
                "database_error": error_message
            }), 500
       
        # If successful, return the result as normal.
        return jsonify(final_result)
    except Exception as e:
        print(f"FATAL ERROR in /analyze route: {e}")
        return jsonify({"error": "An unexpected server error occurred during analysis."}), 500

@app.route("/analyze-screenshot", methods=["POST"])
def analyze_screenshot_api():
    if 'screenshot' not in request.files:
        return jsonify({"error": "No screenshot file provided"}), 400
    file = request.files['screenshot']
    result = analyze_screenshot_with_gemini(file.stream, file.filename)
    if "error" not in result:
        save_screenshot_analysis_to_db(result)
    return jsonify(result)

@app.route("/analyze-news", methods=["POST"])
def analyze_news_api():
    data = request.get_json()
    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400
    text_content = data["text"].strip()
    if not text_content:
        return jsonify({"error": "Text content cannot be empty"}), 400
    if gemini_model:
        analysis_result = analyze_news_with_gemini(text_content)
        if "error" not in analysis_result:
            analysis_result["original_text"] = text_content
            save_news_analysis_to_db(analysis_result)
        return jsonify(analysis_result)
    else:
        return jsonify({"error": "Gemini model not configured for news analysis."}), 500

@app.route("/api/community-threats")
@nocache
def get_community_threats():
    threats = []
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        query = "SELECT url, threat_score FROM site_analysis WHERE flag = 'malicious' AND threat_score >= 80 ORDER BY analysis_timestamp DESC LIMIT 3"
        cursor.execute(query)
        threats = cursor.fetchall()
        for threat in threats:
            threat['score'] = threat.pop('threat_score')
    except Exception as e:
        print(f"Error in get_community_threats: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        if cursor: cursor.close()
    return jsonify(threats)

@app.route("/api/feedback", methods=['POST'])
def handle_feedback_api():
    feedback_data = request.get_json()
    if not feedback_data or not isinstance(feedback_data.get('accurate'), bool) or not feedback_data.get('url'):
        return jsonify({"status": "error", "message": "Invalid feedback payload"}), 400
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        sql = "INSERT INTO analysis_feedback (url, is_accurate, reason, other_text) VALUES (%s, %s, %s, %s)"
        params = (feedback_data.get('url'), feedback_data.get('accurate'), feedback_data.get('reason'), feedback_data.get('other_text'))
        cursor.execute(sql, params)
        conn.commit()
    except Exception as err:
        print(f"ERROR in handling feedback: {err}")
        return jsonify({"status": "error", "message": "Failed to save feedback"}), 500
    finally:
        if cursor: cursor.close()
    return jsonify({"status": "success"})

@app.route("/api/feedback/news", methods=['POST'])
def handle_news_feedback_api():
    feedback_data = request.get_json()
    if not feedback_data or not isinstance(feedback_data.get('accurate'), bool) or not feedback_data.get('text'):
        return jsonify({"status": "error", "message": "Invalid feedback payload"}), 400
    
    # Hash the original text to create a storable identifier
    original_text = feedback_data.get('text')
    text_hash = hashlib.sha256(original_text.encode('utf-8')).hexdigest()

    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        sql = "INSERT INTO fake_news_feedback (original_text_hash, is_accurate, reason, other_text) VALUES (%s, %s, %s, %s)"
        params = (text_hash, feedback_data.get('accurate'), feedback_data.get('reason'), feedback_data.get('other_text'))
        cursor.execute(sql, params)
        conn.commit()
    except Exception as err:
        print(f"ERROR in handling news feedback: {err}")
        return jsonify({"status": "error", "message": "Failed to save feedback"}), 500
    finally:
        if cursor: cursor.close()
    return jsonify({"status": "success"})

@app.route("/admin/feedback")
@login_required
def feedback_dashboard():
    return render_template("feedback_dashboard.html")


@app.route("/api/analyses-stats")
@nocache
def get_analyses_stats():
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        query = """
            SELECT
                COUNT(*) as total_scans,
                AVG(threat_score) as avg_score,
                SUM(CASE WHEN flag = 'legitimate' THEN 1 ELSE 0 END) as legitimate_count,
                SUM(CASE WHEN flag = 'suspicious' THEN 1 ELSE 0 END) as suspicious_count,
                SUM(CASE WHEN flag = 'malicious' THEN 1 ELSE 0 END) as malicious_count
            FROM site_analysis
        """
        cursor.execute(query)
        stats = cursor.fetchone()
        
        if stats and stats['avg_score'] is not None:
            stats['avg_score'] = round(float(stats['avg_score']), 1)
        
        return jsonify(stats)
    except Exception as e:
        print(f"Error fetching stats: {e}")
        return jsonify({"error": "Failed to fetch stats"}), 500
    finally:
        if cursor: cursor.close()

@app.route("/api/all-analyses")
@nocache
def get_all_analyses():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    search_term = request.args.get('search')
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 50))
    offset = (page - 1) * limit

    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        
        base_query = "FROM site_analysis"
        where_clauses = []
        params = []

        if start_date and end_date:
            where_clauses.append("DATE(analysis_timestamp) BETWEEN %s AND %s")
            params.extend([start_date, end_date])
        
        if search_term:
            where_clauses.append("url LIKE %s")
            params.append(f"%{search_term}%")
        
        if where_clauses:
            base_query += " WHERE " + " AND ".join(where_clauses)

        count_query = "SELECT COUNT(*) as total " + base_query
        cursor.execute(count_query, tuple(params))
        total_records = cursor.fetchone()['total']

        data_query = "SELECT id, url, flag, threat_score, analysis_source, analysis_timestamp " + base_query + " ORDER BY analysis_timestamp DESC LIMIT %s OFFSET %s"
        data_params = params + [limit, offset]
        cursor.execute(data_query, tuple(data_params))
        analyses = cursor.fetchall()
        
        total_pages = (total_records + limit - 1) // limit if limit > 0 else 0

        return jsonify({
            "total_records": total_records,
            "page": page,
            "total_pages": total_pages,
            "data": analyses
        })
    except Exception as e:
        print(f"Error fetching all analyses: {e}")
        return jsonify({"error": "Failed to fetch analysis data"}), 500
    finally:
        if cursor: cursor.close()

@app.route("/api/all-news-analyses")
@nocache
def get_all_news_analyses():
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, original_text, fake_news_score, political_bias, analysis_source, analysis_timestamp FROM fake_news_analysis ORDER BY analysis_timestamp DESC LIMIT 100")
        return jsonify(cursor.fetchall())
    except Exception as e:
        print(f"Error fetching all news analyses: {e}")
        return jsonify({"error": "Failed to fetch news analysis data"}), 500
    finally:
        if cursor: cursor.close()

@app.route("/api/all-feedback")
@nocache
def get_all_feedback():
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        # Make sure this line includes 'other_text'
        cursor.execute("SELECT id, url, is_accurate, reason, other_text, feedback_timestamp FROM analysis_feedback ORDER BY feedback_timestamp DESC LIMIT 100")
        return jsonify(cursor.fetchall())
    except Exception as e:
        print(f"Error fetching all feedback: {e}")
        return jsonify({"error": "Failed to fetch feedback data"}), 500
    finally:
        if cursor: cursor.close()

@app.route("/api/all-news-feedback")
@nocache
def get_all_news_feedback():
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        # We don't select the hash as it's not useful for display
        cursor.execute("SELECT id, is_accurate, reason, other_text, feedback_timestamp FROM fake_news_feedback ORDER BY feedback_timestamp DESC LIMIT 100")
        return jsonify(cursor.fetchall())
    except Exception as e:
        print(f"Error fetching all news feedback: {e}")
        return jsonify({"error": "Failed to fetch news feedback data"}), 500
    finally:
        if cursor: cursor.close()

@app.route("/api/delete-analysis/<int:id>", methods=["DELETE"])
def delete_analysis(id):
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM site_analysis WHERE id = %s", (id,))
        conn.commit()
        return jsonify({"status": "success", "message": f"Deleted analysis record {id}"})
    except Exception as e:
        print(f"Error deleting analysis {id}: {e}")
        return jsonify({"error": "Failed to delete"}), 500
    finally:
        if cursor: cursor.close()

@app.route("/api/delete-feedback/<int:id>", methods=["DELETE"])
def delete_feedback(id):
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM analysis_feedback WHERE id = %s", (id,))
        conn.commit()
        return jsonify({"status": "success", "message": f"Deleted feedback record {id}"})
    except Exception as e:
        print(f"Error deleting feedback {id}: {e}")
        return jsonify({"error": "Failed to delete"}), 500
    finally:
        if cursor: cursor.close()

@app.route("/api/delete-news-analysis/<int:id>", methods=["DELETE"])
def delete_news_analysis(id):
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM fake_news_analysis WHERE id = %s", (id,))
        conn.commit()
        return jsonify({"status": "success", "message": f"Deleted news analysis record {id}"})
    except Exception as e:
        print(f"Error deleting news analysis {id}: {e}")
        return jsonify({"error": "Failed to delete"}), 500
    finally:
        if cursor: cursor.close()

@app.route("/api/delete-news-feedback/<int:id>", methods=["DELETE"])
def delete_news_feedback(id):
    cursor = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM fake_news_feedback WHERE id = %s", (id,))
        conn.commit()
        return jsonify({"status": "success", "message": f"Deleted news feedback record {id}"})
    except Exception as e:
        print(f"Error deleting news feedback {id}: {e}")
        return jsonify({"error": "Failed to delete"}), 500
    finally:
        if cursor: cursor.close()

if __name__ == "__main__":
    init_db()
    is_production = os.getenv('RENDER', False)
    port = int(os.getenv('PORT', 5000))

    if is_production:
        print(f"INFO: Running production server on port {port}...")
        serve(app, host='0.0.0.0', port=port)
    else:
        print("INFO: Running development server...")
        app.run(debug=True, host='0.0.0.0', port=port)