# 🚀 Shareb00st3r v2 

Automates Facebook post shares.

## ⚠️ Disclaimer

**Use this tool at your own risk.** Automating interactions with Facebook may violate their Terms of Service and could lead to restrictions or a ban on your account. The developer is not responsible for any consequences that may arise from the use of this script.

## 🛠️ Installation

### General Installation

1.  **Prerequisites:**
    *   Python 3.7+
    *   pip (Python package installer)
    *   Git

2.  **Clone the Repository:**
    Open your terminal or command prompt and run:
    ```bash
    git clone https://github.com/joshuaAposto/ShareBooster.git
    cd ShareBooster
    ```

3.  **(Optional but Recommended) Create and Activate a Virtual Environment:**
    ```bash
    python3 -m venv venv
    ```
    Activate it:
    ```bash
    source venv/bin/activate
    ```

4.  **Install Dependencies:**
    Ensure you are in the `ShareBooster` directory and your virtual environment is activated.
    ```bash
    pip install requests rich
    ```

### Alpine Linux Specific Installation Steps

If you are using Alpine Linux, you might need to install Python, pip, and Git first.

1.  **Update Package List and Install Prerequisites:**
    Open your Alpine terminal and run:
    ```bash
    apk update
    apk add python3 py3-pip git
    ```

2.  **Verify Installation (Optional):**
    ```bash
    python3 --version
    pip3 --version
    git --version
    ```

3.  **Follow General Installation Steps:**
    After installing the prerequisites above, proceed with the "General Installation" steps starting from "Clone the Repository". Use `python3` and `pip3` if `python` and `pip` are not aliased to their Python 3 versions.
    If you encounter issues installing Python packages on Alpine that require compilation, you might need to install build tools:
    ```bash
    apk add build-base python3-dev libffi-dev openssl-dev
    ```

## 🔑 How to Login

1.  **Run the Script:**
    Navigate to the `ShareBooster` directory in your terminal (if not already there) and ensure your virtual environment is activated (if you created one).
    ```bash
    python3 sharebooster.py
    ```

2.  **First-Time Login / No Cached Session:**
    *   The script will prompt you for your **Facebook Email/Username**. Type it and press Enter.
    *   Next, it will prompt for your **Facebook Password**. As you type, the characters will not be displayed on the screen for security. Type your password and press Enter.
    *   The script will attempt to log in. If successful, it will fetch session cookies and save them to a file named `.session.json` in the same directory.

3.  **Subsequent Logins (Cached Session):**
    *   The script will first try to use the saved session from `.session.json`.
    *   If the session is still valid, it will proceed directly to asking for the Post URL.
    *   If the session has expired or is invalid, you will be prompted for your login credentials again, as in the first-time login.

4.  **Clearing Session (Logout):**
    If you need to log out or clear the cached login session, run the script with the `--clear-session` or `--logout` argument:
    ```bash
    python3 sharebooster.py --clear-session
    ```
    This will delete the `.session.json` file, requiring you to log in again on the next run.
