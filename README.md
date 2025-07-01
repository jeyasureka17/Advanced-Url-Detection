🔐 Advanced URL Detector with Hybrid Analysis
This project implements a professional, full-featured desktop application to detect malicious URLs using a hybrid analysis engine. It provides a secure environment for users with a complete authentication system.
The system evaluates URLs based on a multi-layered approach, combining a machine learning model, a rule-based engine, and external API verification to provide a comprehensive and reliable security assessment.

💡 Project Overview
The primary goal is to create a robust tool that can accurately classify URLs as SAFE, POTENTIAL RISK, or MALICIOUS. The system is designed with a professional user experience in mind, from secure login to a clear and informative analysis breakdown.
User Authentication System – A secure system for user registration, login, and password management, featuring an email-based "Forgot Password" flow.
Hybrid URL Analysis – A powerful engine that combines three methods:
Machine Learning: A Random Forest model analyzes lexical features.
Rule-Based Heuristics: A scoring system checks for common phishing and malware indicators (e.g., domain age, suspicious keywords).
External Verification: The VirusTotal API provides a community-backed security score.
Efficient Caching System - A local database cache for VirusTotal results dramatically reduces API calls and improves performance for previously scanned URLs.

🛠️ Technologies Used
Backend & Logic: Python
GUI Framework: Tkinter
Machine Learning: Scikit-learn, Pandas, Joblib
Database: SQLite3 for user data and history caching
Web & Network: Requests, Whois, BeautifulSoup4
Authentication & Security: Hashlib, SMTPlib, python-dotenv

📁 Project Structure
File/Folder	Description
main_app.py	The main Tkinter application, handling all UI frames and user interaction.
url_analyzer.py	Contains the core logic for the hybrid analysis engine.
train.py	Script to train the Random Forest machine learning model.
database_setup.py	Initializes the SQLite database and tables on first run.
config.py	Securely loads API keys and secrets from the .env file.
.env	(Local Only) Stores secret credentials. Not uploaded to GitHub.
.gitignore	Ensures that secret files and caches are not committed to Git.
data/	Contains the url_data_full.csv dataset for training the model.

🔍 How It Works
User Authentication: A user signs up or logs in. Passwords are securely stored as a SHA-256 hash. The "Forgot Password" feature uses an App Password to send a secure reset code via email.
URL Submission: The user enters a URL for analysis.
Cache Check: The system first checks its local database to see if the URL has been scanned recently. If a valid cached result exists, it is returned immediately to save time and API calls.
Hybrid Analysis: If no cached result is found:
The Rule-Based Engine analyzes host and lexical features, assigning a risk score.
The Machine Learning Model predicts the probability of maliciousness based on lexical features.
An API call is made to VirusTotal for an external community score.
Verdict Calculation: The scores from all three sources are combined to produce a final, reliable verdict: SAFE, POTENTIAL RISK, or MALICIOUS.
History & Caching: The result is displayed to the user and saved to the database for future reference and caching.

🧠 Model Performance
Module	Model	Accuracy
URL Detection	Random Forest	~99%
Accuracy based on the validation set after training on the url_data_full.csv dataset. The model excels at identifying patterns in URL structure.

🚀 How to Run
Install Dependencies:
pip install pandas scikit-learn joblib Pillow whois requests beautifulsoup4 python-dote
Configure Secrets:
Create a file named .env in the project root.
Add your credentials to it:
SENDER_EMAIL="your-email@gmail.com"
SENDER_PASSWORD="your-16-character-app-password"
VIRUSTOTAL_API_KEY="your-virustotal-api-key"
Setup Database (Run once):
python database_setup.py
Train Model (Run once):
python train.py
Launch the Application:
python main_app.py
