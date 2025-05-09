from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from rich.align import Align
from rich.padding import Padding
from rich.spinner import Spinner
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, SpinnerColumn
from rich.markup import escape

import urllib.parse
import requests
import json
import sys
import os
import re
import time
from datetime import datetime, timedelta, timezone
import hashlib
import itertools

from ask import prompt_ask

auth_url = "https://b-api.facebook.com/method/auth.login"
business_api = "https://business.facebook.com/content_management"
graph_api = "https://graph.facebook.com/me/feed"

session_cache_file = ".session.json"
request_timeout = 15
share_interval_seconds = 0.0001
max_log_entries = 5000000

class ShareBooster:
    max_share_per_ses = 1000
    contact = "facebook.com/Bogart.Magalpok"

    bilat = ".ratbus.json"

    xor = "how"
    error_border = "bold #FF4136"
    error_text = "bold #FF4136"
    success_border = "bold #2ECC40"
    success_text = "bold #2ECC40"
    info_border = "bold #0074D9"
    info_text = "bold #7FDBFF"
    warning_border = "bold #FF851B"
    warning_text = "bold #FF851B"

    allen_kalbo = "af804fc5d79cf1f861f7964b5437bb327827f452ce37f9d398e171faeb7b99c0"
    welcome_border = "bold #FFDC00"
    welcome_title = "bold #FFBF00"
    credit_original = "italic #B0B0B0"
    credit_modifier = "italic #A0A0FF"
    prompt_bracket = "bold #00FF00"
    prompt_symbol = "bold #00FFFF"
    table_header = "bold #F0F8FF"
    ratbu = 17
    column_attempt = "cyan"
    column_time = "magenta"
    column_details = "dim #D3D3D3"

    tite = "3a1a1e483d12070818"
    pussy = "220004001a16482e07071c030703"

    def _xor_(self, text_bytes, key_bytes):
        return bytes(b ^ k for b, k in zip(text_bytes, itertools.cycle(key_bytes)))

    def ugh(self):
        key_bytes = self.xor.encode('utf-8')
        encrypted_bytes = bytes.fromhex(self.tite)
        decrypted_bytes = self._xor_(encrypted_bytes, key_bytes)
        return decrypted_bytes.decode('utf-8')

    def burat(self):
        key_bytes = self.xor.encode('utf-8')
        encrypted_bytes = bytes.fromhex(self.pussy)
        decrypted_bytes = self._xor_(encrypted_bytes, key_bytes)
        return decrypted_bytes.decode('utf-8')

    def __init__(self):
        self._verify_credits()
        self.stderr = Console(stderr=True, theme=self._create_theme())
        self.stdout = Console(theme=self._create_theme())
        self.session = requests.Session()
        self.post_url = ""
        self.post_id = None
        self.email = None
        self.password = None
        self.cookies_string = ""
        self.access_token = None
        self.cached_data = self._load_cached_data()
        self.cookies_string = self.cached_data.get("cookies_string", "")

        self.share_attempt_count = 0
        self.success_share_count = 0
        self.error_share_count = 0

        self.current_ip = None
        self.ratbus_data = {}

    def _verify_credits(self):
        try:
            decrypted_original_author = self.ugh()
            decrypted_modifier_name = self.burat()
        except Exception:
            print("CRITICAL ERROR: Credit decryption failed. Script may be corrupted.")
            print("Exiting due to integrity issue.")
            sys.exit(102)

        current_combined = f"{decrypted_original_author}|{decrypted_modifier_name}"
        current_allen_kalbo = hashlib.sha256(current_combined.encode()).hexdigest()

        if current_allen_kalbo != self.allen_kalbo:
            print("CRITICAL ERROR: Script integrity compromised. Credits have been modified or key is incorrect.")
            print(f"This script is intended to credit:")
            print(f"  Original Author: (Protected)")
            print(f"  Modified by: (Protected)")
            print("Exiting due to unauthorized modification.")
            sys.exit(101)

    def _create_theme(self):
        from rich.theme import Theme
        return Theme({
            "error": self.error_text,
            "success": self.success_text,
            "info": self.info_text,
            "warning": self.warning_text,
            "prompt_bracket_text": self.prompt_bracket,
            "prompt_symbol": self.prompt_symbol,
        })

    def _load_cached_data(self):
        try:
            with open(session_cache_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
        except Exception as e:
            print(f"[ERROR] Failed to load cached data: {e}", file=sys.stderr)
            sys.exit(1)

    def _save_cached_data(self):
        try:
            with open(session_cache_file, "w") as f:
                json.dump(self.cached_data, f, indent=2)
        except Exception as e:
            self._display_message(f"Failed to save cached data: {e}",
                                  style_type="error")

    def _display_message(self,
                         message,
                         title="Info",
                         style_type="info",
                         panel=True):
        console_method = self.stderr.print if style_type == "error" else self.stdout.print
        border_style = self.info_border
        text_style = f"[{style_type}]{message}[/{style_type}]"
        if style_type == "error":
            border_style = self.error_border
        elif style_type == "success":
            border_style = self.success_border
        elif style_type == "warning":
            border_style = self.warning_border

        if panel:
            console_method(
                Panel(Text.from_markup(text_style),
                      title=f"[{style_type}]{title}[/{style_type}]",
                      border_style=border_style,
                      expand=False))
        else:
            console_method(
                Text.from_markup(
                    f"[{style_type}]{title}: {message}[/{style_type}]"))

    def _clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")

    def _get_business_page_headers(self):
        return {
            'authority':
            'business.facebook.com',
            'accept':
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'accept-language':
            'en-US,en;q=0.9',
            'cache-control':
            'max-age=0',
            'cookie':
            self.cookies_string,
            'referer':
            'https://www.facebook.com/',
            'sec-ch-ua':
            '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
            'sec-ch-ua-mobile':
            '?0',
            'sec-ch-ua-platform':
            '"Linux"',
            'sec-fetch-dest':
            'document',
            'sec-fetch-mode':
            'navigate',
            'sec-fetch-site':
            'same-origin',
            'sec-fetch-user':
            '?1',
            'upgrade-insecure-requests':
            '1',
            'user-agent':
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'
        }

    def _prompt_credentials(self):
        self.stdout.print(
            Panel(Text("Facebook login required.", style="info"),
                  border_style=self.info_border))
        self.email = prompt_ask(self.stdout, "Email/Username", prompt_indicator="~")
        self.password = prompt_ask(self.stdout, "Password",
                                         prompt_indicator="~",
                                         password=True)

    def fetch_cookies(self):
        with self.stdout.status(Text.from_markup(
                "[info]Authenticating and fetching cookies...[/info]"),
                                spinner="dots12"):
            params = {
                'adid': 'e3a395f9-84b6-44f6-a0ce-fe83e934fd4d',
                'email': self.email,
                'password': self.password,
                'format': 'json',
                'device_id': '67f431b8-640b-4f73-a077-acc5d3125b21',
                'cpl': 'true',
                'family_device_id': '67f431b8-640b-4f73-a077-acc5d3125b21',
                'locale': 'en_US',
                'client_country_code': 'US',
                'credentials_type': 'device_based_login_password',
                'generate_session_cookies': '1',
                'generate_analytics_claim': '1',
                'generate_machine_id': '1',
                'currently_logged_in_userid': '0',
                'irisSeqID': '1',
                'try_num': '1',
                'enroll_misauth': 'false',
                'meta_inf_fbmeta': 'NO_FILE',
                'source': 'login',
                'machine_id': 'KBz5fEj0GAvVAhtufg3nMDYG',
                'fb_api_req_friendly_name': 'authenticate',
                'fb_api_caller_class':
                'com.facebook.account.login.protocol.Fb4aAuthHandler',
                'api_key': '882a8490361da98702bf97a021ddc14d',
                'access_token': '350685531728|62f8ce9f74b12f84c123cc23437a4a32'
            }
            full_url = auth_url + "?" + urllib.parse.urlencode(params)
            try:
                response = self.session.get(full_url, timeout=request_timeout)
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.Timeout:
                self._display_message("Login request timed out.",
                                      title="Login Error",
                                      style_type="error")
                return False
            except requests.exceptions.RequestException as e:
                self._display_message(f"Network error during login: {e}",
                                      title="Login Error",
                                      style_type="error")
                return False
            except json.JSONDecodeError:
                self._display_message(
                    f"Invalid response from login server: {response.text[:200]}",
                    title="Login Error",
                    style_type="error")
                return False
        if 'session_cookies' in data:
            self.cookies_string = "; ".join(
                f"{cookie['name']}={cookie['value']}"
                for cookie in data['session_cookies'])
            self.cached_data['cookies_string'] = self.cookies_string
            self._save_cached_data()
            self._display_message("Cookies obtained successfully!",
                                  title="Login Success",
                                  style_type="success")
            return True
        else:
            error_msg = data.get(
                'error_msg',
                data.get('error', {}).get('message', str(data)))
            self._display_message(
                f"Failed to get cookies. API Response: {error_msg}",
                title="Login Failed",
                style_type="error")
            return False

    def fetch_access_token(self):
        with self.stdout.status(
                Text.from_markup("[info]Fetching access token...[/info]"),
                spinner="moon"):
            headers = self._get_business_page_headers()
            try:
                response = self.session.get(business_api,
                                            headers=headers,
                                            timeout=request_timeout)
                response.raise_for_status()
                content = response.text
                token_match = re.search(r'["\'](EAAG\w+)["\']', content)
                if token_match:
                    self.access_token = token_match.group(1)
                    self._display_message(
                        "Access token obtained successfully.",
                        title="Token Acquired",
                        style_type="success")
                    return True
                else:
                    self._display_message(
                        "Could not extract access token. Page structure might have changed or cookies are invalid.",
                        title="Token Error",
                        style_type="error")
                    if "login" in response.url.lower(
                    ) or "checkpoint" in response.url.lower():
                        self._display_message(
                            "Redirected to login/checkpoint. Cookies might be expired.",
                            title="Token Error",
                            style_type="warning")
                        self.cookies_string = ""
                        self.cached_data.pop('cookies_string', None)
                        self._save_cached_data()
                    return False
            except requests.exceptions.Timeout:
                self._display_message("Request for access token timed out.",
                                      title="Token Error",
                                      style_type="error")
                return False
            except requests.exceptions.RequestException as e:
                self._display_message(
                    f"Network error while fetching access token: {e}",
                    title="Token Error",
                    style_type="error")
                return False
            except AttributeError:
                self._display_message(
                    "Failed to parse access token structure (AttributeError).",
                    title="Token Error",
                    style_type="error")
                return False


    def _generate_live_layout(self, log_table, max_shares_this_session):
        layout = Layout(name="root")
        layout.split_column(Layout(name="header", size=3), Layout(name="log"))

        succeeded_text_style = self.success_text
        if self.success_share_count >= max_shares_this_session and max_shares_this_session > 0:
            succeeded_text_style = "bold green"

        summary_text = Text.assemble(
            ("Session Shares: ", "bold"),
            (f"{self.success_share_count}", succeeded_text_style),
            ("/", "bold"),
            (f"{max_shares_this_session}", "bold orange1"),
            (" Succeeded", succeeded_text_style),
            (" | Attempted: ", "bold"),
            (f"{self.share_attempt_count}", self.column_attempt),
            (" | Failed: ", "bold"),
            (f"{self.error_share_count}", self.error_text)
        )
        header_panel = Panel(Align.center(summary_text),
                             title="[bold]Live Share Statistics (Current Session)[/bold]",
                             border_style=self.info_border,
                             padding=(0, 1))
        layout["header"].update(header_panel)
        layout["log"].update(log_table)
        return layout

    def perform_share(self, max_shares_this_session):
        share_url = f"{graph_api}?link=https://m.facebook.com/{self.post_id}&published=0&access_token={self.access_token}"
        share_headers = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate',
            'connection': 'keep-alive',
            'cookie': self.cookies_string,
            'host': 'graph.facebook.com',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36 Edg/90.0.818.51'
        }
        log_table = Table(title=f"Sharing Log for Post ID: {self.post_id} (Session Limit: {max_shares_this_session})",
                          show_lines=False,
                          expand=True,
                          border_style=self.info_border)
        log_table.add_column("Attempt", justify="right", style=self.column_attempt, no_wrap=True, min_width=7)
        log_table.add_column("Time", style=self.column_time, min_width=10)
        log_table.add_column("Status", min_width=15)
        log_table.add_column("Details", style=self.column_details, overflow="fold", min_width=40)

        current_live_instance = None
        loop_exited_cleanly = False

        try:
            with Live(self._generate_live_layout(log_table, max_shares_this_session),
                      console=self.stdout,
                      refresh_per_second=4,
                      screen=False,
                      vertical_overflow="visible") as live:
                current_live_instance = live
                try:
                    while True:
                        if self.success_share_count >= max_shares_this_session:
                            live.update(Text(f"\n[success]Session share limit ({max_shares_this_session}) reached. Ending current session.[/success]", justify="center"), refresh=True)
                            time.sleep(1)
                            loop_exited_cleanly = True
                            break

                        self.share_attempt_count += 1
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        status_icon, status_text, details_text, status_style = "", "", "", ""
                        raw_response_debug = ""

                        try:
                            response = self.session.post(
                                share_url,
                                headers=share_headers,
                                timeout=request_timeout)
                            raw_response_debug = response.text
                            data = response.json()
                            response.raise_for_status()

                            if 'id' in data:
                                self.success_share_count += 1
                                status_icon, status_text, details_text, status_style = "", "Success", f"FB ID: {data['id']}", self.success_text
                            else:
                                self.error_share_count += 1
                                error_detail = data.get('error', {}).get('message', str(data))
                                status_icon, status_text, details_text, status_style = "", "Failed (API)", error_detail, self.error_text
                        except requests.exceptions.HTTPError as e:
                            self.error_share_count += 1
                            status_icon, status_text = "", f"HTTP Error {e.response.status_code}"
                            error_message = f"HTTP {e.response.status_code}"
                            fb_error_detail = ""
                            try:
                                fb_error_data = e.response.json()
                                fb_error_detail = fb_error_data.get('error', {}).get('message', str(fb_error_data))
                            except json.JSONDecodeError:
                                fb_error_detail = e.response.text[:200]

                            if fb_error_detail: error_message = fb_error_detail
                            details_text, status_style = error_message, self.error_text
                        except requests.exceptions.Timeout:
                            self.error_share_count += 1
                            status_icon, status_text, details_text, status_style = "", "Timeout", f"Request timed out after {request_timeout}s.", self.warning_text
                        except requests.exceptions.RequestException as e:
                            self.error_share_count += 1
                            status_icon, status_text, details_text, status_style = "", "Network Error", str(e), self.error_text
                        except json.JSONDecodeError:
                            self.error_share_count += 1
                            snippet = raw_response_debug[:100] if raw_response_debug else "Response was empty or not captured."
                            status_icon, status_text, details_text, status_style = 
