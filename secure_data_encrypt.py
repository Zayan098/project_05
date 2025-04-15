import os
import json
import time
import hashlib
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes  # ✅ Added import
import streamlit as st

DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"  
LOCKOUT_DURATION = 60

# === Section login details ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# === if data is load ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # ✅ Fixed here
        length=32,
        salt=SALT,
        iterations=100000
    )
    key = kdf.derive(passkey.encode())
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try: 
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

stored_data = load_data()

# === Section login details ===
st.title(" 🔐 Secure Data Encryption system")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("Welcome to the My 🔐 Secure Data Encryption system made using streamlit UI!")
    st.markdown("Develop a streamlit-based secure data and retrieval system where: Users store data with a unique passkey. Users decrypt data by providing the correct passkey. Multiple failed attempts result in a forced reauthorization (Login page). The system operates entirely in memory, without external databases.")

# === User Registration ===
elif choice == "Register":
    st.subheader("📝 Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("Username already exists ⚠️")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("User registered successfully! ✅")
        else:
            st.warning("Both fields are required ⚠️")

elif choice == "Login":
    st.subheader("🔑 User Login")
    
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"Too many failed attempts. Please wait {remaining} seconds before trying again 🔁.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"Welcome {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining_attempts = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. {remaining_attempts} attempts left.")
            
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🔴 Too many failed attempts. Locked for 60sec 🔒.")
                st.stop()

# Data Store Section
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.error("Please login first! 🔑")
    else:
        st.subheader("💾 Store Encrypted Data")
        data = st.text_area("Enter your data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")

        if st.button("Encrypt And Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("Data encrypted and stored successfully! ✅")
            else:
                st.error("All fields must be filled")

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first! 🔑")
    else:
        st.subheader("🔍 Retrieve Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No data found for the user.")
        else:
            st.write("Encrypted data entries:")
            for i, entry in enumerate(user_data):
                st.code(entry, language="text")
            encrypted_input = st.text_area("Enter the encrypted data to decrypt")
            passkey = st.text_input("Enter passkey To Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"✅ Decrypted data: {result}")
                else:
                    st.error("❌ Failed to decrypt data. Check your passkey or data.")
