# secure_app.py
import streamlit as st
import bcrypt
import time

st.set_page_config(page_title="Secure Auth System", page_icon="🔐")

st.markdown("<h1 style='text-align:center;'>🔐 Secure Login / Signup System</h1>", unsafe_allow_html=True)

# Initialize session state
if "users" not in st.session_state:
    st.session_state["users"] = {}  # {username: hashed_password}
if "failed_attempts" not in st.session_state:
    st.session_state["failed_attempts"] = {}

menu = st.sidebar.radio("Menu", ["Signup", "Login"])

def signup():
    st.subheader("📝 Create an Account")
    username = st.text_input("Enter Username")
    password = st.text_input("Enter Password", type="password")

    if st.button("Signup"):
        if username in st.session_state["users"]:
            st.error("⚠️ Username already exists!")
        elif len(password) < 8:
            st.warning("⚠️ Password must be at least 8 characters.")
        else:
            hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
            st.session_state["users"][username] = hashed
            st.success(f"✅ Account created for {username}")

def login():
    st.subheader("🔑 Login to Your Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        # Brute force protection
        if st.session_state["failed_attempts"].get(username, 0) >= 3:
            st.error("🚫 Account locked due to multiple failed attempts. Try again later.")
            time.sleep(3)
            return

        if username in st.session_state["users"] and bcrypt.checkpw(password.encode("utf-8"), st.session_state["users"][username]):
            st.success(f"✅ Welcome {username}!")
            st.session_state["failed_attempts"][username] = 0
        else:
            st.error("❌ Invalid username or password")
            st.session_state["failed_attempts"][username] = st.session_state["failed_attempts"].get(username, 0) + 1

if menu == "Signup":
    signup()
elif menu == "Login":
    login()
