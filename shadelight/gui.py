import streamlit as st
import subprocess
import os
import tempfile

st.set_page_config(
    page_title="Shadelight GUI",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# --- Style ---
st.markdown("""
    <style>
        body {
            background-color: #000;
            color: #f1f1f1;
        }
        .reportview-container .main .block-container {
            padding-top: 2rem;
            padding-bottom: 2rem;
        }
        h1, h2, h3, h4, h5 {
            color: #b873ff;
        }
        .stButton>button {
            background-color: #b873ff;
            color: black;
            font-weight: bold;
        }
    </style>
""", unsafe_allow_html=True)

# --- Header ---
st.title("Shadelight")
st.markdown("<p style='color:#ccc;'>A sleek frontend for scanning your system.</p>", unsafe_allow_html=True)

# --- Feature Tabs ---
tabs = st.tabs(["🦠 Malware Scan", "🌐 Port Scan", "🚧 Coming Soon"])

# --- Malware Scan ---
with tabs[0]:
    st.subheader("Malware Signature Scan")
    target_path = st.text_input("Enter file or folder path:", value=os.path.expanduser("~"))

    if st.button("Start Malware Scan"):
        st.info("Running malware scan...")
        progress_bar = st.progress(0)
        output = st.empty()

        try:
            cmd = f"python -m shadelight 0.0.0.0/32 --ports 0 --signature-scan \"{target_path}\""
            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as temp_log:
                result = subprocess.run(cmd, shell=True, stdout=temp_log, stderr=subprocess.STDOUT)
                temp_log.flush()
                with open(temp_log.name) as f:
                    lines = f.readlines()
                    total = len(lines)
                    for i, line in enumerate(lines):
                        progress_bar.progress((i + 1) / total)
                        output.text("".join(lines[:i + 1][-10:]))
                os.unlink(temp_log.name)
            st.success("Scan complete.")
        except Exception as e:
            st.error(f"Error during scan: {e}")

# --- Port Scan ---
with tabs[1]:
    st.subheader("Network Port Scan")
    subnet = st.text_input("Enter subnet (e.g., 192.168.1.0/24):", value="127.0.0.1/32")
    ports = st.text_input("Enter comma-separated ports (e.g., 22,80,443):", value="80")

    if st.button("Start Port Scan"):
        st.info("Running port scan...")
        progress_bar = st.progress(0)
        output = st.empty()

        try:
            cmd = f"python -m shadelight {subnet} --ports {ports}"
            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as temp_log:
                result = subprocess.run(cmd, shell=True, stdout=temp_log, stderr=subprocess.STDOUT)
                temp_log.flush()
                with open(temp_log.name) as f:
                    lines = f.readlines()
                    total = len(lines)
                    for i, line in enumerate(lines):
                        progress_bar.progress((i + 1) / total)
                        output.text("".join(lines[:i + 1][-10:]))
                os.unlink(temp_log.name)
            st.success("Scan complete.")
        except Exception as e:
            st.error(f"Error during scan: {e}")

# --- Coming Soon ---
with tabs[2]:
    st.subheader("More features are on the way...")
    st.markdown("<p style='color:#777;'>Risk scoring, real-time alerts, and more will be available in future releases.</p>", unsafe_allow_html=True)
