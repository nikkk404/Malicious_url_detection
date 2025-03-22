from flask import Flask, render_template, request, url_for
from markupsafe import escape  # Use escape from markupsafe instead of Flask
import google.generativeai as genai
import os
from dotenv import load_dotenv
import validators
import logging
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Set up the Google API Key
api_key = os.getenv("API_KEY")
if not api_key:
    logging.error("API_KEY is not set in the environment variables.")
    raise ValueError("API_KEY is required to run the application.")
os.environ["GOOGLE_API_KEY"] = api_key
genai.configure(api_key=api_key)

# Initialize the Gemini model
model = genai.GenerativeModel("gemini-2.0-flash")

MAX_URL_LENGTH = 200
VALID_URL_CLASS = ["benign", "phishing", "malware", "suspicious", "defacement"] # Include suspicious
#VALID_URL_CLASS = ["benign", "phishing", "malware", "defacement"]

def url_detection(url):
    prompt = f"""
    You are an expert AI model specializing in identifying and classifying malicious URLs. Your primary goal is to accurately detect URLs that pose a security risk, including those hosting malware, phishing sites, and other unsafe content.

    **Key Considerations for Classification:**

    *   **Malware Distribution:** URLs that directly host or redirect to downloads containing viruses, trojans, ransomware, worms, or other malicious software. Look for suspicious file extensions (e.g., .exe, .dll, .zip, .scr) and deceptive download practices (e.g., automatic downloads, fake update prompts).
    *   **Phishing Attacks:** URLs that mimic legitimate websites to steal user credentials, financial information, or other personal data. Analyze the domain name for misspellings, unusual subdomains, and the presence of security indicators (e.g., fake SSL certificates, deceptive login forms).
    *   **Exploit Kits:** URLs that host exploit kits, which automatically scan visitors' browsers for vulnerabilities and deliver malware. These sites often use obfuscated code and redirect to multiple URLs.
    *   **Drive-by Downloads:** URLs that initiate malware downloads without the user's explicit consent.
    *   **Social Engineering:** URLs that use deceptive tactics to trick users into performing actions that compromise their security (e.g., fake surveys, lottery scams, urgent warnings).

    **Classification Categories:**

    1.  **Benign:** Safe, trusted, and non-malicious websites (e.g., google.com, wikipedia.org, nytimes.com).
    2.  **Phishing:** Fraudulent websites designed to steal personal information through deception (e.g., misspelled domains, fake login pages).
    3.  **Malware:** URLs that directly host or distribute malicious software (e.g., viruses, trojans, ransomware).
    4.  **Suspicious:** URLs that exhibit some potentially malicious characteristics but require further investigation (e.g., new domains, unusual redirects, shortened URLs).
    5.  **Defacement:** Websites that have been hacked and display unauthorized content.

    **Example URLs and Classifications:**

    *   **Benign:** "https://www.google.com/"
    *   **Phishing:** "http://secure-login.paypa1.com/" (misspelled domain)
    *   **Phishing:** "http://yourbank.com.login.example.com/" (deceptive subdomain)
    *   **Malware:** "http://malware-site.ru/evil.exe" (explicit malware download)
    *   **Malware:** "http://legitimate-site.com/update.exe" (compromised legitimate site)
    *   **Suspicious:** "http://bit.ly/dangerous-link" (shortened URL)
    *   **Suspicious:** "http://newly-registered-domain.com/" (newly registered domain with little content)
     *   **Defacement:** "http://hacked-website.com/" (Website displaying unauthorized content)

    **Input URL:** {url}

    **Output Format:**

    -   Return only a single string representing the classification (e.g., "benign", "phishing", "malware", "suspicious", "defacement").
    -   Always return a classification, even if uncertain. If the URL appears suspicious but cannot be definitively classified, return "suspicious". Return only in lowercase.

    Analyze the URL and return the most accurate classification based on the criteria above. Prioritize the detection of malicious URLs.
    Note: Don't return empty or null, at any cost return the corrected class
    """
    try:
        response = model.generate_content(prompt)
        if response and response.text:
            classification = response.text.strip().lower()
            if classification in VALID_URL_CLASS:
                return classification
            else:
                logging.warning(f"Unexpected URL classification: {classification}")
                return "unknown"  # Explicitly handle unexpected responses
        else:
            logging.warning("Gemini API returned an empty or invalid response.")
            return "unknown"
    except Exception as e:
        logging.exception(f"Error during URL detection: {e}")
        return "error"

@app.route('/', methods=['GET', 'POST'])
def predict_url():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()

        # Input validation and sanitization
        if not url:
            return render_template("index.html", message="URL cannot be empty.")

        if len(url) > MAX_URL_LENGTH:
            return render_template("index.html", message=f"URL is too long (maximum {MAX_URL_LENGTH} characters).")

        if not validators.url(url):
            return render_template("index.html", message="Invalid URL format.", input_url=url)

        url = escape(url)  # Sanitize for XSS protection

        try:
            classification = url_detection(url)
            return render_template("index.html", input_url=url, predicted_class=classification)
        except Exception as e:
            logging.error(f"Error during URL prediction: {e}")
            return render_template("index.html", message="An error occurred during URL prediction.", input_url=url)
    return render_template("index.html")  # Render the form initially

if __name__ == '__main__':
    app.run(debug=True)