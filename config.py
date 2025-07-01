# Create this new file: config.py

import os
from dotenv import load_dotenv

# This line loads the variables from your .env file into the environment
load_dotenv()

# We now safely access the secrets using os.getenv()
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Add a check to ensure the variables were loaded correctly
if not all([SENDER_EMAIL, SENDER_PASSWORD, VIRUSTOTAL_API_KEY]):
    print("❌ CRITICAL ERROR: One or more environment variables are missing.")
    print("Please check that your .env file is created and contains SENDER_EMAIL, SENDER_PASSWORD, and VIRUSTOTAL_API_KEY.")
    # In a real app, you might raise an exception here
    # raise ValueError("Missing critical environment variables.")