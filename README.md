# 🔐 Advanced URL Detector with Hybrid Analysis

This project is a professional-grade desktop application that detects malicious URLs using a hybrid analysis engine. It is designed with user security and accuracy in mind, offering a secure login system, smart caching, and intelligent threat detection based on machine learning, heuristic rules, and external threat intelligence APIs.

The application enables users to check the safety of URLs and classify them into three categories: **SAFE**, **POTENTIAL RISK**, or **MALICIOUS**. It provides clear verdicts, historical scanning records, and robust performance for everyday and professional use.

---

The system uses a multi-layered detection approach:

- **Machine Learning (Random Forest)** trained on URL lexical features using the `url_data_full.csv` dataset.
- **Rule-Based Heuristics**, including domain age checks, suspicious keywords, and abnormal patterns.
- **External API Integration** with **VirusTotal** to verify against community and vendor reports.

A **local SQLite3 database cache** is used to store past results for 24 hours to reduce repeated scans and API calls.

---

### Key Features

- ✅ URL Classification: Accurately flags safe or suspicious URLs
- 🔐 Secure Authentication System: Includes user registration, login, and password reset via email
- 🧠 Hybrid Analysis Engine: Combines ML prediction, heuristic scoring, and VirusTotal validation
- 💾 Smart Caching: Avoids repeated API calls by saving recent scan data
- 🖥️ GUI Application: Built with Python’s Tkinter for a native desktop experience

---

### Technologies Used

- **Python (Backend & Logic)**
- **Tkinter (GUI Framework)**
- **Scikit-learn, Pandas, Joblib (Machine Learning)**
- **SQLite3 (Local Database for users and cache)**
- **Requests, Whois, BeautifulSoup4 (Web tools)**
- **Hashlib, SMTPlib, python-dotenv (Security & Email Reset)**

---

### How It Works

Users can log in or register to securely use the tool. Upon entering a URL:

1. The system checks if the URL has been scanned in the last 24 hours.
2. If not cached:
   - Heuristic rules analyze the structure and content of the URL.
   - The trained machine learning model predicts if the URL is malicious.
   - An external call to the VirusTotal API gathers threat intelligence.
3. The system combines all three assessments to generate a final verdict.
4. The result is saved to the local cache and displayed in the GUI.

The password reset feature uses an email-based OTP system powered by Gmail (App Passwords) to ensure account recovery is secure.

---

### Model Performance

- **Random Forest Classifier**
- **Achieved ~99% Accuracy** on the validation set
- Features include domain length, presence of IP address, special characters, suspicious tokens, etc.

---

### Project Files Overview

- `main_app.py` – Launches the Tkinter interface and handles user flow
- `url_analyzer.py` – Contains the core URL detection logic
- `train.py` – Trains and saves the ML model
- `database_setup.py` – Creates necessary tables and schema
- `config.py` – Loads environment secrets for API/email securely
- `data/url_data_full.csv` – Training dataset
- `.env` – Stores sensitive credentials (not tracked by Git)
- `.gitignore` – Prevents secrets and cache files from being pushed

---

This application is suitable for educational, professional, and enterprise scenarios where reliable URL scanning is critical. The combination of local intelligence and external validation makes it fast, safe, and highly accurate.
