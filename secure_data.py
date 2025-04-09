import streamlit as st # type: ignore
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet # type: ignore
from cryptography.hazmat.primitives import hashes # type: ignore
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # type: ignore
import base64

# Configuration
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds
DATA_FILE = "secure_data.json"
MASTER_PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()  # Hashed master password

# Initialize session state
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'locked_out' not in st.session_state:
    st.session_state.locked_out = False
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

# Generate or load encryption key
def get_fernet_key():
    # In production, this should be properly secured and not regenerated each time
    salt = b'some_salt'  # Should be unique and secret in production
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(b"password"))  # Use a real password in production
    return key

KEY = get_fernet_key()
cipher = Fernet(KEY)

# Load data from file if it exists
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

# Save data to file
def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

stored_data = load_data()

# Function to hash passkey with PBKDF2
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    else:
        salt = base64.b64decode(salt.encode())
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    hashed = base64.b64encode(kdf.derive(passkey.encode())).decode()
    salt_str = base64.b64encode(salt).decode()
    return f"{salt_str}${hashed}"

# Function to verify passkey
def verify_passkey(passkey, stored_hash):
    try:
        salt_str, stored_hashed = stored_hash.split('$')
        new_hash = hash_passkey(passkey, salt_str)
        return new_hash == stored_hash
    except:
        return False

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text):
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Check if user is locked out
if st.session_state.locked_out:
    remaining_time = LOCKOUT_TIME - (time.time() - st.session_state.lockout_time)
    if remaining_time > 0:
        st.warning(f"🔒 Account locked. Please try again in {int(remaining_time/60)} minutes {int(remaining_time%60)} seconds.")
    else:
        st.session_state.locked_out = False
        st.session_state.failed_attempts = 0

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
if st.session_state.locked_out:
    choice = "Login"
else:
    choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.write("### Features:")
    st.write("- Secure encryption using Fernet (AES-128)")
    st.write("- PBKDF2 key derivation for passkey hashing")
    st.write("- Account lockout after 3 failed attempts")
    st.write("- Persistent data storage in encrypted JSON file")
    
    if st.button("Clear All Data (Admin Only)"):
        st.session_state.authenticated = False
        st.experimental_rerun()

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    username = st.text_input("Enter a username (for your reference):")
    user_data = st.text_area("Enter Data to Encrypt:")
    passkey = st.text_input("Enter Passkey:", type="password")
    passkey_confirm = st.text_input("Confirm Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if not username:
            st.error("Username is required!")
        elif not user_data:
            st.error("Data to encrypt is required!")
        elif not passkey:
            st.error("Passkey is required!")
        elif passkey != passkey_confirm:
            st.error("Passkeys do not match!")
        else:
            encrypted_text = encrypt_data(user_data)
            hashed_passkey = hash_passkey(passkey)
            stored_data[username] = {
                "encrypted_text": encrypted_text, 
                "passkey": hashed_passkey,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            save_data(stored_data)
            st.success("✅ Data stored securely!")
            st.write("### Your encrypted data:")
            st.code(encrypted_text)
            st.warning("⚠️ Please save this encrypted text as you'll need it to retrieve your data later.")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    username = st.text_input("Enter your username:")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if not username or not encrypted_text or not passkey:
            st.error("All fields are required!")
        elif username not in stored_data:
            st.error("Username not found!")
        elif stored_data[username]["encrypted_text"] != encrypted_text:
            st.error("Encrypted data doesn't match the username!")
        else:
            # Verify passkey first
            if verify_passkey(passkey, stored_data[username]["passkey"]):
                decrypted_text = decrypt_data(encrypted_text)
                if decrypted_text:
                    st.session_state.failed_attempts = 0
                    st.success("✅ Decryption successful!")
                    st.text_area("Decrypted Data:", value=decrypted_text, height=200)
                else:
                    st.error("❌ Decryption failed! Data may be corrupted.")
            else:
                st.session_state.failed_attempts += 1
                if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                    st.session_state.locked_out = True
                    st.session_state.lockout_time = time.time()
                    st.error("🔒 Too many failed attempts! Account locked for 5 minutes.")
                    st.experimental_rerun()
                else:
                    remaining_attempts = MAX_ATTEMPTS - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining_attempts}")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    
    if st.session_state.locked_out:
        remaining_time = LOCKOUT_TIME - (time.time() - st.session_state.lockout_time)
        if remaining_time > 0:
            st.warning(f"Account locked. Please try again in {int(remaining_time/60)} minutes {int(remaining_time%60)} seconds.")
        else:
            st.session_state.locked_out = False
            st.session_state.failed_attempts = 0
    
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if hashlib.sha256(login_pass.encode()).hexdigest() == MASTER_PASSWORD_HASH:
            st.session_state.failed_attempts = 0
            st.session_state.locked_out = False
            st.session_state.authenticated = True
            st.success("✅ Reauthorized successfully! You can now try retrieving data again.")
            time.sleep(2)
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")

    if st.session_state.authenticated and st.button("Admin: View All Data"):
        st.subheader("All Stored Data (Admin View)")
        st.write(stored_data)