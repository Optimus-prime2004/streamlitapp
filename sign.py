import streamlit as st
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from datetime import timedelta
import uuid  # For API key generation
from jose import JWTError, jwt
from passlib.context import CryptContext
from typing import Optional
import pandas as pd
import socket
import time

# Secret key for JWT encoding & decoding (Keep this secure)
SECRET_KEY = "csc123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Email configuration (Replace with your credentials)
SENDER_EMAIL = "sololeveling4216@gmail.com"
SENDER_PASSWORD = "gtva tqeq sbae yprn"
DEVELOPER_EMAIL = "vvalliappan2004@gmail.com"  # Used as fallback, signup email is used normally

# Admin Access Password
ADMIN_PASSWORD = "adminpassword"  # Define ADMIN_PASSWORD here

# Initialize fake_users_db in session state
if "fake_users_db" not in st.session_state:
    st.session_state["fake_users_db"] = {}

# Access the database from session state
fake_users_db = st.session_state["fake_users_db"]

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Login Attempts (Simulate a table for pending requests)
if "login_attempts" not in st.session_state:
    st.session_state["login_attempts"] = []  # List of dictionaries

# Admin Logged In State
if "admin_logged_in" not in st.session_state:
    st.session_state["admin_logged_in"] = False

# Logged In Users Table
if "logged_in_users" not in st.session_state:
    st.session_state["logged_in_users"] = []

# Function to send an email
def send_email(subject, body, recipient_email):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient_email  # Use the signup email now

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
            smtp.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())
        st.success(f"Email sent to {recipient_email} successfully!")
    except Exception as e:
        st.error(f"Error sending email: {e}")


# Function to get the client's IP address
def get_client_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"  # Default fallback


# Function to verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Function to hash password
def get_password_hash(password):
    return pwd_context.hash(password)

# Function to generate API key
def generate_api_key():
    return str(uuid.uuid4())


# Function to authenticate user
def authenticate_user(db, username: str, password: str, ip_address: str):
    user = db.get(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False

    if user["disabled"]:  # Access is revoked
        return False

    if user["original_ip"] is None:
        user["original_ip"] = ip_address  # Store the original IP
        user["ip_timestamp"] = datetime.now() # Store the timestamp

        # IMPORTANT: Update the database in session_state!
        st.session_state["fake_users_db"][username] = user

    # Add the user to the logged_in_users list
    st.session_state["logged_in_users"].append({
        "username": username,
        "ip_address": ip_address,
        "login_time": datetime.now()
    })

    return user  # Return the user object


# Function to create JWT token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# Token endpoint for login
def login_for_access_token(username, password, ip_address):
    user = authenticate_user(fake_users_db, username, password, ip_address)

    if not user:

        st.session_state["login_attempts"].append({
            "username": username,
            "ip_address": ip_address,
            "timestamp": datetime.now()
        })
        st.warning("Invalid username or password.  Request needs to be approved for access.")
        return None

    access_token = create_access_token(data={"sub": user["username"], "ip": ip_address})
    st.session_state["access_token"] = f"Bearer {access_token}"
    st.success("Login successful")
    return user


# Function to extract user from token
def get_current_user():
    token = st.session_state.get("access_token")
    if not token:
        return None

    token = token.replace("Bearer ", "")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
    except JWTError:
        return None

    user = fake_users_db.get(username)
    if user is None or user["disabled"]:
        return None

    return user


# Admin endpoint to grant/revoke user access
def update_user_status(username: str, status: bool):
    user = fake_users_db.get(username)
    if not user:
        st.error("User not found")
        return "User not found"

    user["disabled"] = not status  # True = Revoked, False = Granted

    # Update the database in session_state!
    st.session_state["fake_users_db"][username]["disabled"] = not status

    status_message = f"User {username} is now {'granted access' if not status else 'revoked'}"
    st.success(status_message)  # Display success message
    return "User is granted" if not status else "User is revoked"


# Logout endpoint
def logout():
    if "access_token" in st.session_state:
        del st.session_state["access_token"]
    st.success("Logout successful")

def send_grant_access_email(username, ip_address):
    email_body = f"Login request from user: {username} with IP: {ip_address} at {datetime.now()}.\n\nPlease grant access if appropriate."
    send_email( "Login Request", email_body, DEVELOPER_EMAIL)

def admin_login():
    st.subheader("Admin Login")
    admin_password = st.text_input("Admin Password", type="password")
    if st.button("Admin Login"):
        if admin_password == ADMIN_PASSWORD:
            st.session_state["admin_logged_in"] = True
            st.success("Admin login successful!")
            st.rerun()
        else:
            st.error("Incorrect admin password")

def sign_up_page():
    st.title("Sign Up")

    name = st.text_input("Full Name")
    email = st.text_input("Email Address")

    if st.button("Create API Key"):
        if not name or not email:
            st.error("Please enter both name and email.")
            return

        api_key = generate_api_key()  # Generate the API key
        hashed_password = get_password_hash(api_key)  # Hash it

        # Store user data
        username = email # Using email as username
        st.session_state["fake_users_db"][username] = {
            "username": username,
            "full_name": name,
            "email": email,
            "hashed_password": hashed_password,
            "disabled": False,
            "original_ip": None,
            "ip_timestamp": None,
        }

        # Send email to the user
        email_body = f"Your API key is: {api_key}\nUse this as password to login.\nKeep it safe!\nYour Hashed Password is:{hashed_password} "
        send_email("Your API Key", email_body, email)

        st.success("API key created and sent to your email address.")


# Streamlit UI
def main():
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ["Login", "Sign Up", "Admin Controls"])

    if page == "Login":
        login_page()
    elif page == "Sign Up":
        sign_up_page()
    elif page == "Admin Controls":
        if st.session_state["admin_logged_in"]:
            admin_controls_page()
        else:
            admin_login()  # Show admin login if not logged in


def login_page():
    st.title("Login Page")

    if "access_token" not in st.session_state:
        username = st.text_input("Username (Email)")
        password = st.text_input("Password (API Key)", type="password")

        if st.button("Login"):
            ip_address = get_client_ip()  # Get the client's IP address
            user = login_for_access_token(username, password, ip_address)
            if user:
                st.session_state["logged_in_user"] = user
                st.rerun()
    else:
        st.write("You are logged in!")
        if st.button("Logout"):
            logout()
            st.rerun()
            st.session_state.pop("logged_in_user", None)  # remove the user from the login session


def admin_controls_page():
    st.title("Admin Controls")

    # Show login requests
    if st.session_state["login_attempts"]:
        st.subheader("Pending Login Requests")
        df = pd.DataFrame(st.session_state["login_attempts"])
        df['timestamp'] = df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
        st.dataframe(df)

    st.subheader("User Management")

    user_list = list(fake_users_db.keys())
    if not user_list:
        st.info("No users in the database.")
        return

    data = []
    for i, username in enumerate(user_list):
        user = fake_users_db[username]
        ip_info = f"{user['original_ip']} ({user['ip_timestamp'].strftime('%Y-%m-%d %H:%M:%S')})" if user['original_ip'] else "Not yet logged in"

        data.append({
            "Serial No": i + 1,
            "Username": username,
            "Original IP Address (Date/Time)": ip_info,
            "Access Granted": not user["disabled"]
        })

    df = pd.DataFrame(data)
    st.dataframe(df)

    selected_username = st.selectbox("Select User", user_list)
    user = fake_users_db[selected_username]

    col1, col2, col3 = st.columns(3) # Add a new column for the email button

    with col1:
        if st.button("Grant Access", key=f"grant_{selected_username}"):
            message = update_user_status(selected_username, True)  # Grant access
            st.rerun()
            st.write(message)

    with col2:
        if st.button("Revoke Access", key=f"revoke_{selected_username}"):
            message = update_user_status(selected_username, False)  # Revoke access
            st.rerun()
            st.write(message)

    with col3:
        if st.button("Send Grant Access Email", key=f"email_{selected_username}"):
            send_grant_access_email(selected_username, user.get("original_ip", "Unknown IP"))

    # Logged In Users Table
    st.subheader("Logged-In Users")
    if st.session_state["logged_in_users"]:
        login_df = pd.DataFrame(st.session_state["logged_in_users"])
        login_df['login_time'] = login_df['login_time'].dt.strftime('%Y-%m-%d %H:%M:%S')
        st.dataframe(login_df)
    else:
        st.info("No users are currently logged in.")

if __name__ == "__main__":
    main()