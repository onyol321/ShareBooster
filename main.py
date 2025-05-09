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
    contact = "facebook.com/Bogart"

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

    tite = "2a0010091d03482800091f18"
    pussy = ""

    def _xor_(self, text_bytes, key_bytes):
        return bytes(b ^ k for b, k in zip(text_bytes, itertools.cycle(key_bytes)))

    def ugh(self):
        key_bytes = self.xor.encode('utf-8')
        encrypted_bytes = bytes.fromhex(self.tite)
        decrypted_bytes = self._xor_(encrypted_bytes, key_bytes)
        return decrypted_bytes.decode('utf-8')

    def burat(self):
        return ""  # No modifier shown
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
        pass

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
                            status_icon, status_text, details_text, status_style = "", "JSON Error", f"Invalid JSON: {snippet}...", self.error_text
                        except Exception as e:
                            self.error_share_count += 1
                            status_icon, status_text, details_text, status_style = "", "Unknown Loop Error", str(e), self.error_text

                        if log_table.rows and len(log_table.rows) >= max_log_entries:
                            if max_log_entries > 0 : log_table.rows.pop(0)
                        if max_log_entries > 0:
                            log_table.add_row(str(self.share_attempt_count), timestamp, Text.from_markup(f"{status_icon} [{status_style}]{status_text}[/{status_style}]"), details_text)

                        live.update(self._generate_live_layout(log_table, max_shares_this_session))
                        time.sleep(share_interval_seconds)

                except KeyboardInterrupt:
                    if current_live_instance:
                        current_live_instance.update(Text("\n[warning]Share process for this session interrupted. Finalizing...[/warning]", justify="center"), refresh=True)
                        time.sleep(0.5)
                    raise

        except KeyboardInterrupt:
             raise
        except Exception as e:
            if not isinstance(e, KeyboardInterrupt):
                self.stderr.print(Panel(Text.from_markup(f"[error]Error in perform_share's Live context or unhandled from loop: {type(e).__name__}: {e}[/error]"),
                                      title="[error]Critical Share Loop Error[/error]", border_style=self.error_border))
                import traceback; traceback.print_exc(file=sys.stderr)
            raise


    def extract_post_id(self):
        patterns = [
            r"pfbid([\w-]+)",
            r"(?:posts|videos|photos|permalink)/(?:[\w.-]+/)?(\d+|pfbid0[\w.-]+)",
            r"(?:story_fbid=|fbid=|v=)(\d+|pfbid0[\w.-]+)"
        ]
        for pattern in patterns:
            match = re.search(pattern, self.post_url)
            if match:
                potential_id = match.group(1)
                if pattern == r"pfbid([\w-]+)":
                    self.post_id = "pfbid" + potential_id
                elif "pfbid" in match.group(0) and not potential_id.startswith("pfbid"):
                    pfbid_match_in_full = re.search(r"(pfbid[\w.-]+)", match.group(0))
                    if pfbid_match_in_full: self.post_id = pfbid_match_in_full.group(1)
                    else: self.post_id = potential_id
                else:
                    self.post_id = potential_id

                self.stdout.print(Panel(Text.from_markup(f"[success]Extracted Post ID: [bold cyan]{self.post_id}[/bold cyan][/success]"), border_style=self.success_border))
                return
        self._display_message("Could not automatically extract Post ID from URL.", title="Input Required", style_type="warning")
        self.stdout.print(Panel(Text.from_markup("Examples:\n- From `.../posts/123...` -> `123...`\n- From `...story_fbid=pfbidABC...` -> `pfbidABC...`"),
                               title="[prompt_bracket_text]Manual Post ID Entry[/prompt_bracket_text]", border_style=self.prompt_bracket, padding=(0,1)))
        self.post_id = prompt_ask(self.stdout, "Post ID", prompt_indicator="id")
        if not self.post_id:
            self._display_message("Post ID cannot be empty. Exiting.", title="Invalid Input", style_type="error")
            sys.exit(1)


    def check_cookies_validity(self):
        if not self.cookies_string: return False
        session_ok = False
        report_errors = None
        with self.stdout.status(Text.from_markup("[info]Verifying session...[/info]"), spinner="hearts"):
            headers = self._get_business_page_headers()
            try:
                response = self.session.get(business_api, headers=headers, timeout=10, allow_redirects=True)
                if response.ok and \
                   ("content_management" in response.url or "business_suite" in response.url) and \
                   ("logout" in response.text or "composer" in response.text or "EAAG" in response.text):
                    session_ok = True
                else:
                    if "login" in response.url.lower() or "checkpoint" in response.url.lower():
                        report_errors = ("Cached session redirected to login/checkpoint. Cookies likely expired.", "Session Invalid", "warning")
                    else:
                         report_errors = (f"Session verification failed. Status: {response.status_code}. URL: {response.url}", "Session Invalid", "warning")
                    session_ok = False
            except requests.exceptions.Timeout:
                report_errors = ("Timeout while verifying session.", "Session Check Failed", "error"); session_ok = False
            except requests.exceptions.RequestException as e:
                error_summary = str(e).splitlines()[0] if str(e).splitlines() else str(e)
                report_errors = (f"Network error during session verification: {error_summary}", "Session Check Failed", "error"); session_ok = False
            time.sleep(0.2)
        if report_errors:
            msg, title, style = report_errors
            self._display_message(msg, title=title, style_type=style, panel=False)
        elif session_ok: self.stdout.print(Text.from_markup(" [dim]Session active.[/dim]"))
        return session_ok

    def _display_welcome_message(self):
        self._clear_screen()
        original_author_name = self.ugh()
        modifier_name = self.burat()

        title_text = Text("Shareb00st3r v2", style=self.welcome_title, justify="center")
        original_credit_text = Text.from_markup(f"Made by [bold cyan]{original_author_name}[/bold cyan]", style=self.credit_original, justify="center")
        
        plan_info_header = Text("\nPlan Information", style="bold yellow", justify="center")
        free_plan_notice = Text.from_markup(
            f"[#FFFFE0]You are currently on the [bold yellow]Free Plan[/bold yellow].[/]", justify="center"
        )
        ratbu_info = Text.from_markup(
            f"[#FFFFE0]This includes a [bold orange1]{self.ratbu}-minute system ratbu[/bold orange1] after [bold cyan]{self.max_share_per_ses}[/bold cyan] shares.[/]", justify="center"
        )
        premium_upsell = Text.from_markup(
            f"[#FFFFE0]For a [bold green]Premium Plan[/bold green] (no ratbus, etc.), contact me:[/]\n"
            f"[link={self.contact}][underline blue]{escape(self.contact)}[/underline blue][/link]",
            justify="center"
        )

        welcomes_content = Text("\n").join([
            title_text,
            original_credit_text,
            
            plan_info_header,
            free_plan_notice,
            ratbu_info,
            premium_upsell
        ])
        welcomes_content.justify = "center"

        welcomes = Panel(
            Align.center(welcomes_content),
            title=f"[bold {self.welcome_title}]Welcome[/bold {self.welcome_title}]",
            border_style=self.welcome_border,
            padding=(1,2)
        )
        self.stdout.print(Padding(Align.center(welcomes), (1,0,1,0)))


    def _reset(self):
        self.share_attempt_count = 0
        self.success_share_count = 0
        self.error_share_count = 0

    def _wait_with_countdown(self, duration_seconds, console, reason_message="System Cooldown"):
        console.print(Padding(
            Text.from_markup(
                f"[info]This {self.ratbu}-minute ratbu is part of the Free Plan.[/info]\n"
                f"[info]Consider upgrading to [bold green]Premium[/bold green] for uninterrupted boosting! Contact: [link={self.contact}][underline blue]{escape(self.contact)}[/underline blue][/link][/info]"
            ), (1,0,1,0),
        ))

        total_minutes = duration_seconds / 60
        ratbu_message_display = f"{reason_message}: Waiting for {total_minutes:.1f} minutes..."
        console.print(Padding(f"[info]{ratbu_message_display}[/info]", (0,0,1,0)))

        try:
            with Progress(
                SpinnerColumn(spinner_name="dots"),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=None),
                TextColumn("[progress.percentage]{task.percentage:>3.1f}%"),
                TimeRemainingColumn(),
                console=console,
                transient=False,
                refresh_per_second=1
            ) as progress:

                wait_task = progress.add_task(f"{reason_message} active...", total=duration_seconds)

                while not progress.tasks[wait_task].finished:
                    time.sleep(0.1)
                    progress.update(wait_task, advance=0.1)

            console.print(Padding(f"[info]{reason_message} finished. Resuming...[/info]",(1,0,1,0)))

        except KeyboardInterrupt:
            console.print(f"\n[warning]{reason_message} wait interrupted by user.[/warning]")
            raise

    def get_public_ip(self):
        try:
            response = requests.get("https://api.ipify.org?format=json", timeout=5)
            response.raise_for_status()
            ip_address = response.json()["ip"]
            return ip_address
        except requests.exceptions.Timeout:
            self._display_message("Timeout while retrieving network identifier.", title="Network Error", style_type="error", panel=False)
        except requests.exceptions.RequestException as e:
            self._display_message(f"Could not retrieve network identifier: {e}", title="Network Error", style_type="error", panel=False)
        except (KeyError, json.JSONDecodeError):
            self._display_message("Invalid response from network identification service.", title="Network Error", style_type="error", panel=False)
        return None

    def load_ip_ratbus(self):
        try:
            with open(self.bilat, "r") as f:
                data = json.load(f)
                now_utc = datetime.now(timezone.utc)
                active_ratbus = {}
                for ip, end_time_iso in data.items():
                    try:
                        ratbu_end_time = datetime.fromisoformat(end_time_iso)
                        if ratbu_end_time.tzinfo is None:
                             ratbu_end_time = ratbu_end_time.replace(tzinfo=timezone.utc)
                        if ratbu_end_time > now_utc:
                            active_ratbus[ip] = end_time_iso
                    except ValueError:
                        self.stderr.print(f"[warning]Corrupted ratbu entry in '{self.bilat}'. Skipping.[/warning]")
                if len(active_ratbus) != len(data):
                    try:
                        with open(self.bilat, "w") as f_clean:
                            json.dump(active_ratbus, f_clean, indent=2)
                    except Exception as e_save:
                        self._display_message(f"Failed to save cleaned ratbu data: {e_save}", style_type="error")
                return active_ratbus
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            self._display_message(f"Error decoding ratbu file ('{self.bilat}'). Please check or delete it.", title="Cooldown File Error", style_type="error")
            return {}
        except Exception as e:
            self._display_message(f"Failed to load ratbu data: {e}", style_type="error")
            return {}

    def save_ip_ratbus(self):
        try:
            with open(self.bilat, "w") as f:
                json.dump(self.ratbus_data, f, indent=2)
        except Exception as e:
            self._display_message(f"Failed to save ratbu data: {e}", style_type="error")

    def set_ratbu(self, ip_address, duration_minutes):
        if not ip_address:
            return

        now_utc = datetime.now(timezone.utc)
        ratbu_end_time = now_utc + timedelta(minutes=duration_minutes)
        self.ratbus_data[ip_address] = ratbu_end_time.isoformat()
        self.save_ip_ratbus()
        self.stdout.print(f"[info]System Cooldown initiated.[/info]")


    def get_ip_ratbu_remaining_seconds(self, ip_address):
        if not ip_address or ip_address not in self.ratbus_data:
            return 0

        ratbu_end_iso = self.ratbus_data[ip_address]
        try:
            ratbu_end_time = datetime.fromisoformat(ratbu_end_iso)
            if ratbu_end_time.tzinfo is None:
                ratbu_end_time = ratbu_end_time.replace(tzinfo=timezone.utc)

            now_utc = datetime.now(timezone.utc)

            if ratbu_end_time > now_utc:
                return (ratbu_end_time - now_utc).total_seconds()
            else:
                del self.ratbus_data[ip_address]
                self.save_ip_ratbus()
                return 0
        except ValueError:
            self._display_message(f"Invalid ratbu timestamp format. Clearing entry.", style_type="error")
            if ip_address in self.ratbus_data:
                del self.ratbus_data[ip_address]
                self.save_ip_ratbus()
            return 0

    def run(self):
        self._display_welcome_message()
        time.sleep(0.5)

        self.current_ip = self.get_public_ip()
        if not self.current_ip:
            self._display_message("Unable to determine network identifier. Cooldown cannot be enforced or checked. Exiting.", title="Critical Network Error", style_type="error")
            sys.exit(1)

        self.ratbus_data = self.load_ip_ratbus()
        remaining_ratbu_seconds = self.get_ip_ratbu_remaining_seconds(self.current_ip)

        if remaining_ratbu_seconds > 0:
            remaining_minutes = remaining_ratbu_seconds / 60
            self.stdout.print(Panel(
                Text.from_markup(
                    f"[warning]System is currently in a ratbu period.[/warning]\n"
                    f"[warning]Remaining: {remaining_minutes:.1f} minutes.[/warning]"
                ),
                title="[warning]Cooldown Active[/warning]",
                border_style=self.warning_border,
                padding=(1,2)
            ))
            try:
                self._wait_with_countdown(int(remaining_ratbu_seconds), self.stdout, reason_message="System Cooldown")
                if self.current_ip in self.ratbus_data:
                    if self.get_ip_ratbu_remaining_seconds(self.current_ip) == 0:
                         self.stdout.print(f"[info]System Cooldown has expired.[/info]")
            except KeyboardInterrupt:
                self.stdout.print("\n[warning]Cooldown wait interrupted. Exiting.[/warning]")
                sys.exit(0)

        if self.cookies_string and not self.check_cookies_validity():
            self.cookies_string = ""
            self.cached_data.pop('cookies_string', None)
            self._save_cached_data()
            self._display_message("Cached session was invalid and has been cleared.", title="Session Cleared", style_type="warning")

        if not self.cookies_string:
            self.stdout.print()
            self._prompt_credentials()
            if not self.fetch_cookies():
                self._display_message("Login failed. Cannot continue.", title="Fatal Error", style_type="error")
                sys.exit(1)

        self.stdout.print()
        self.post_url = prompt_ask(self.stdout, "Facebook Post URL", prompt_indicator="~")
        self.extract_post_id()

        if not self.fetch_access_token():
            self._display_message(
                "Could not obtain access token. Possible reasons:\n- Cookies expired (delete .session.json & re-login)\n- FB API/page structure changed\n- Account restrictions",
                title="Fatal Error", style_type="error")
            sys.exit(1)

        session_count = 0
        try:
            while True:
                session_count += 1
                self._reset()
                self._clear_screen()

                self.stdout.print(Panel(
                    Text.from_markup(f"[info]Starting Share Session #{session_count} for Post ID: [bold cyan]{self.post_id}[/bold cyan].[/info]\n"
                                     f"[info]Limit for this session ([bold yellow]Free Plan[/bold yellow]): [bold yellow]{self.max_share_per_ses}[/bold yellow] successful shares.[/info]\n"
                                     f"[info]Press [bold red]Ctrl+C[/bold red] to stop the script entirely.[/info]"),
                    title="[info]New Share Session[/info]",
                    border_style=self.info_border,
                    padding=(1,2)
                ))

                self.perform_share(max_shares_this_session=self.max_share_per_ses)

                self.stdout.print(Panel(
                    Text.from_markup(
                        f"[success]Share Session #{session_count} completed.[/success]\n"
                        f"[info]Successful shares in this session: {self.success_share_count}/{self.max_share_per_ses}[/info]\n"
                        f"[info]Total attempted in this session: {self.share_attempt_count}[/info]\n"
                        f"[info]Initiating {self.ratbu}-minute system ratbu (Free Plan feature).[/info]"
                    ),
                    title="[success]Session Ended[/success]",
                    border_style=self.success_border,
                    padding=(1,2)
                ))

                self.set_ratbu(self.current_ip, self.ratbu)
                self._wait_with_countdown(self.ratbu * 60, self.stdout, reason_message="Post-Session Cooldown")

        except KeyboardInterrupt:
            if self.current_ip:
                self.stdout.print(f"\n[warning]Process interrupted. Setting {self.ratbu}-minute system ratbu.[/warning]")
                self.set_ratbu(self.current_ip, self.ratbu)
            else:
                self.stdout.print("\n[warning]Process interrupted. Cooldown could not be set.[/warning]")
            raise

        except Exception as e:
            raise


if __name__ == "__main__":
    if "--clear-session" in sys.argv or "--logout" in sys.argv:
        print(f"[] Attempting to clear cached session data from '{session_cache_file}'...")
        try:
            if os.path.exists(session_cache_file):
                os.remove(session_cache_file)
                print(f"[+] Successfully deleted '{session_cache_file}'.")
            else:
                print(f"[] '{session_cache_file}' not found. No cached session to clear.")
        except OSError as e: print(f"[!] Error deleting '{session_cache_file}': {e}")
        except Exception as e: print(f"[!] An unexpected error occurred while clearing session: {e}")

        bilat_to_clear = ShareBooster.bilat
        print(f"[*] Attempting to clear ratbu data from '{bilat_to_clear}'...")
        try:
            if os.path.exists(bilat_to_clear):
                os.remove(bilat_to_clear)
                print(f"[+] Successfully deleted '{bilat_to_clear}'.")
            else:
                print(f"[*] '{bilat_to_clear}' not found. No ratbu data to clear.")
        except OSError as e: print(f"[!] Error deleting '{bilat_to_clear}': {e}")
        except Exception as e: print(f"[!] An unexpected error occurred while clearing ratbu data: {e}")

        print("[*] Cache clearing process finished. You may need to log in again on the next run.")
        sys.exit(0)

    booster = ShareBooster()
    try:
        booster.run()
    except KeyboardInterrupt:
        booster.stdout.print("\n")
        final_summary_text = Text.assemble(
            ("Sharing process interrupted by user.\n", "bold warning"),
            ("Attempted: ", "bold"), (f"{booster.share_attempt_count}", booster.column_attempt),
            (" | Succeeded: ", "bold"), (f"{booster.success_share_count}", booster.success_text),
            (" | Failed: ", "bold"), (f"{booster.error_share_count}", booster.error_text)
        )

        booster.stdout.print(
            Panel(Align.center(final_summary_text),
                  title="[warning]Process Halted[/warning]",
                  border_style=booster.warning_border,
                  padding=(1,2) ))
        booster.stdout.print(Text.from_markup("\n[info]Exiting Shareb00st3r. Thank you for using![/info]"))
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    except Exception as e:
        booster.stderr.print(Panel(Text.from_markup(
            f"[error]An unexpected critical error occurred in the main execution: {type(e).__name__}: {e}\nThis is likely a bug. Please report it.[/error]"
        ), title="[error]Unhandled Exception[/error]", border_style=booster.error_border))
        import traceback
        booster.stderr.print(f"\n[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)