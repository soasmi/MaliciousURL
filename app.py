import os
import re
import json
import requests
import tldextract
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Database setup
Base = declarative_base()
engine = create_engine('sqlite:///scans.db')
Session = sessionmaker(bind=engine)

class ScanLog(Base):
    __tablename__ = 'scan_logs'
    
    id = Column(Integer, primary_key=True)
    url = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    verdict = Column(String)
    threat_categories = Column(JSON)
    vt_report_id = Column(String)

Base.metadata.create_all(engine)

# VirusTotal API configuration
VT_API_KEY = os.getenv('VT_API_KEY')
VT_API_URL = 'https://www.virustotal.com/vtapi/v2/url/report'

def analyze_url_patterns(url):
    """Perform basic pattern analysis on the URL."""
    suspicious_patterns = {
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'suspicious_tld': r'\.(xyz|tk|ml|ga|cf|gq|pw|cc|top|work|site|online|click|link|bid|win|loan|review|download|xyz|tk|ml|ga|cf|gq|pw|cc|top|work|site|online|click|link|bid|win|loan|review|download)\b',
        'suspicious_keywords': r'(login|signin|account|secure|verify|confirm|password|bank|paypal|amazon|ebay|apple|microsoft|google|facebook|twitter|instagram|linkedin|netflix|spotify|disney|hulu|hbo|prime|amazon|ebay|walmart|target|bestbuy|costco|home|depot|lowes|walmart|target|bestbuy|costco|home|depot|lowes)',
        'shortened_url': r'(bit\.ly|t\.co|goo\.gl|tinyurl\.com|is\.gd|cli\.gs|ow\.ly|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|tr\.im|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|twitthis\.com|ht\.ly|alturl\.com|tiny\.pl|url\.ie|u\.mm|link\.zip\.net)'
    }
    
    threats = []
    for pattern_name, pattern in suspicious_patterns.items():
        if re.search(pattern, url, re.IGNORECASE):
            threats.append(pattern_name)
    
    return threats

def get_virustotal_report(url):
    """Get URL report from VirusTotal."""
    params = {
        'apikey': VT_API_KEY,
        'resource': url
    }
    
    try:
        response = requests.get(VT_API_URL, params=params)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error fetching VirusTotal report: {e}")
        return None

def determine_verdict(pattern_threats, vt_report):
    """Determine the final verdict based on pattern analysis and VT report."""
    if not vt_report:
        return "Unknown", []
    
    positives = vt_report.get('positives', 0)
    total = vt_report.get('total', 0)
    
    if positives > 5:
        return "Malicious", pattern_threats
    elif positives > 0 or pattern_threats:
        return "Suspicious", pattern_threats
    return "Safe", []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_url():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Perform pattern analysis
    pattern_threats = analyze_url_patterns(url)
    
    # Get VirusTotal report
    vt_report = get_virustotal_report(url)
    
    # Determine verdict
    verdict, threats = determine_verdict(pattern_threats, vt_report)
    
    # Log the scan
    session = Session()
    scan_log = ScanLog(
        url=url,
        verdict=verdict,
        threat_categories=json.dumps(threats),
        vt_report_id=vt_report.get('scan_id') if vt_report else None
    )
    session.add(scan_log)
    session.commit()
    session.close()
    
    return jsonify({
        'verdict': verdict,
        'threats': threats,
        'vt_report': vt_report,
        'scan_id': vt_report.get('scan_id') if vt_report else None
    })

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """REST API endpoint for URL scanning."""
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'No URL provided'}), 400
    
    url = data['url']
    pattern_threats = analyze_url_patterns(url)
    vt_report = get_virustotal_report(url)
    verdict, threats = determine_verdict(pattern_threats, vt_report)
    
    return jsonify({
        'verdict': verdict,
        'threats': threats,
        'vt_report': vt_report,
        'scan_id': vt_report.get('scan_id') if vt_report else None
    })

if __name__ == '__main__':
    app.run(debug=True) 