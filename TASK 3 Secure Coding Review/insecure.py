# insecure_app.py
import streamlit as st

st.title("🔓 Insecure Login/Signup System")

if "users" not in st.session_state:
    st.session_state["users"] = {}  # {username: password}

menu = st.sidebar.radio("Menu", ["Signup", "Login"])

if menu == "Signup":
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Signup"):
        st.session_state["users"][username] = password
        st.success("Signup successful!")

elif menu == "Login":
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in st.session_state["users"] and st.session_state["users"][username] == password:
            st.success(f"Welcome {username}! ✅")
        else:
            st.error("Invalid credentials ❌")
