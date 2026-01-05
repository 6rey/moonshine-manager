"""
Eclypse Client with Google SSO Support
Desktop application for VDI management with SSO authentication
"""

import customtkinter as ctk
from tkinter import ttk, messagebox, scrolledtext
import requests
import subprocess
import threading
import time
import urllib3
import jwt
import os
import webbrowser
import secrets
from flask import Flask, request, jsonify

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
DEFAULT_API_URL = "https://n8nua.pp.ua"
MOONLIGHT_EXEC = "C:/moonlight/Moonlight.exe"
CONFIG_FILE = "client_config.txt"

# Google SSO Configuration
# TODO: Replace these with your actual Google OAuth credentials
# Get from: https://console.cloud.google.com/apis/credentials
GOOGLE_CLIENT_ID = "your-google-client-id.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "your-google-client-secret"

# Sunshine ports
SUNSHINE_HTTPS_PORT = 47989
SUNSHINE_HTTP_PORT = 47984
SUNSHINE_ALT_PORT = 47990


class GoogleSSOHandler:
    """Handles Google OAuth2 authentication flow"""
    
    def __init__(self, client_id, redirect_uri="http://localhost:8080/callback"):
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.app = Flask(__name__)
        self.token = None
        self.error = None
        self.setup_routes()
        
    def setup_routes(self):
        @self.app.route('/callback')
        def callback():
            code = request.args.get('code')
            error = request.args.get('error')
            
            if error:
                self.error = error
                return jsonify({"status": "error", "error": error})
            
            if code:
                # Exchange code for token
                token_data = self.exchange_code_for_token(code)
                if token_data:
                    self.token = token_data
                    return jsonify({
                        "status": "success", 
                        "message": "Authentication successful! You can close this window."
                    })
                else:
                    self.error = "Token exchange failed"
                    return jsonify({"status": "error", "message": "Token exchange failed"})
            
            return jsonify({"status": "error", "message": "No code received"})
    
    def exchange_code_for_token(self, code):
        """Exchange authorization code for access token"""
        try:
            token_url = "https://oauth2.googleapis.com/token"
            data = {
                "code": code,
                "client_id": self.client_id,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": self.redirect_uri,
                "grant_type": "authorization_code"
            }
            
            response = requests.post(token_url, data=data)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"Token exchange error: {e}")
            return None
    
    def start_server(self):
        """Start Flask server in a thread"""
        def run():
            self.app.run(host='localhost', port=8080, debug=False, use_reloader=False)
        
        server_thread = threading.Thread(target=run, daemon=True)
        server_thread.start()
        time.sleep(1)  # Wait for server to start
    
    def get_auth_url(self):
        """Generate Google OAuth URL"""
        scope = "openid email profile"
        state = secrets.token_urlsafe(32)
        
        auth_url = (
            f"https://accounts.google.com/o/oauth2/v2/auth?"
            f"response_type=code&"
            f"client_id={self.client_id}&"
            f"redirect_uri={self.redirect_uri}&"
            f"scope={scope}&"
            f"state={state}&"
            f"access_type=offline"
        )
        return auth_url
    
    def authenticate(self):
        """Perform full authentication flow"""
        self.start_server()
        
        # Open browser
        auth_url = self.get_auth_url()
        webbrowser.open(auth_url)
        
        # Wait for callback (max 60 seconds)
        start_time = time.time()
        while time.time() - start_time < 60:
            if self.token:
                return {"success": True, "token_data": self.token}
            if self.error:
                return {"success": False, "error": self.error}
            time.sleep(0.5)
        
        return {"success": False, "error": "Timeout waiting for authentication"}


def get_google_user_info(access_token):
    """Get user information from Google API"""
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers=headers
        )
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error getting user info: {e}")
        return None


class EclypseApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Eclypse Client - SSO Enabled")
        self.root.geometry("900x700")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.token = None
        self.headers = None
        self.current_user = None
        self.user_role = None
        self.user_email = None
        self.verify_ssl = False
        
        # Load API URL at startup
        self.api_url = self._load_api_url()
        
        # Main container
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Login area (visible at startup)
        self.setup_login_frame()
        
        # Main area (visible after login)
        self.content_frame = ctk.CTkFrame(self.main_frame)
        
        # Log area
        self.log_frame = ctk.CTkFrame(self.root)
        self.log_frame.pack(fill="x", padx=10, pady=(0, 10), side="bottom")
        
        self.log_area = scrolledtext.ScrolledText(self.log_frame, height=6)
        self.log_area.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.log("Application started.")
        self.log(f"Current API URL: {self.api_url}")
        self.log("SSO functionality enabled - Google login available")
    
    def _load_api_url(self):
        """Loads API URL from configuration file."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    url = f.readline().strip()
                    if url:
                        return url
            except Exception as e:
                self.log(f"Error reading configuration file: {str(e)}")
        return DEFAULT_API_URL

    def _save_api_url(self, url):
        """Saves API URL to configuration file."""
        try:
            with open(CONFIG_FILE, 'w') as f:
                f.write(url)
            self.log(f"API URL saved: {url}")
        except Exception as e:
            self.log(f"Error saving API URL: {str(e)}")
    
    def setup_login_frame(self):
        """Sets up the login screen with SSO support"""
        self.login_frame = ctk.CTkFrame(self.main_frame)
        self.login_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        login_title = ctk.CTkLabel(self.login_frame, text="Eclypse Login", font=("Arial", 18))
        login_title.pack(pady=20)
        
        # --- API URL field (initially hidden) ---
        self.api_url_frame = ctk.CTkFrame(self.login_frame)
        
        api_url_label = ctk.CTkLabel(self.api_url_frame, text="API URL:")
        api_url_label.pack(pady=(10, 0))
        self.api_url_entry = ctk.CTkEntry(self.api_url_frame, width=300)
        self.api_url_entry.pack(pady=5)
        self.api_url_entry.insert(0, self.api_url)
        
        # Traditional login fields
        username_label = ctk.CTkLabel(self.login_frame, text="Username:")
        username_label.pack(pady=(10, 0))
        self.username_entry = ctk.CTkEntry(self.login_frame, width=200)
        self.username_entry.pack(pady=5)
        
        password_label = ctk.CTkLabel(self.login_frame, text="Password:")
        password_label.pack(pady=(10, 0))
        self.password_entry = ctk.CTkEntry(self.login_frame, width=200, show="•")
        self.password_entry.pack(pady=5)
        
        # SSL verification option
        ssl_frame = ctk.CTkFrame(self.login_frame)
        ssl_frame.pack(pady=10)
        
        self.ssl_var = ctk.BooleanVar(value=self.verify_ssl)
        self.ssl_checkbox = ctk.CTkCheckBox(
            ssl_frame, 
            text="Verify SSL certificates", 
            variable=self.ssl_var, 
            command=self.toggle_ssl_verification
        )
        self.ssl_checkbox.pack(side="left", padx=5)
        
        ssl_info_btn = ctk.CTkButton(ssl_frame, text="ℹ️", width=30, command=self.show_ssl_info)
        ssl_info_btn.pack(side="left", padx=5)
        
        # Show API URL checkbox
        self.show_api_url_var = ctk.BooleanVar(value=False)
        self.show_api_url_checkbox = ctk.CTkCheckBox(
            self.login_frame, 
            text="Show API URL field", 
            variable=self.show_api_url_var, 
            command=self.toggle_api_url_visibility
        )
        self.show_api_url_checkbox.pack(pady=5)
        
        # Traditional login button
        login_button = ctk.CTkButton(self.login_frame, text="Login", command=self.authenticate)
        login_button.pack(pady=10)
        
        # SSO Section
        sso_separator = ctk.CTkLabel(self.login_frame, text="─ OR ─")
        sso_separator.pack(pady=10)
        
        sso_title = ctk.CTkLabel(self.login_frame, text="Single Sign-On", font=("Arial", 14))
        sso_title.pack(pady=5)
        
        # SSO buttons frame
        sso_buttons_frame = ctk.CTkFrame(self.login_frame)
        sso_buttons_frame.pack(pady=10)
        
        # Google SSO button
        google_btn = ctk.CTkButton(
            sso_buttons_frame,
            text="Login with Google",
            fg_color="#4285F4",
            hover_color="#357ABD",
            width=200,
            command=self.google_sso_login
        )
        google_btn.pack(pady=5)
        
        # SAML button (placeholder)
        saml_btn = ctk.CTkButton(
            sso_buttons_frame,
            text="Login with SAML",
            fg_color="#6C757D",
            width=200,
            command=self.saml_login
        )
        saml_btn.pack(pady=5)
        
        # Security warning
        self.show_ssl_warning()
        self.toggle_api_url_visibility()
    
    def toggle_api_url_visibility(self):
        """Shows or hides the API URL input field."""
        if self.show_api_url_var.get():
            self.api_url_frame.pack(pady=5)
        else:
            self.api_url_frame.pack_forget()

    def toggle_ssl_verification(self):
        """Enables or disables SSL verification"""
        self.verify_ssl = self.ssl_var.get()
        self.log(f"SSL verification {'enabled' if self.verify_ssl else 'disabled'}")
        self.show_ssl_warning()
        
    def show_ssl_warning(self):
        """Displays a warning if SSL verification is disabled"""
        # Remove existing warning
        for widget in self.login_frame.winfo_children():
            if hasattr(widget, 'ssl_warning_tag') and widget.ssl_warning_tag:
                widget.destroy()
                
        # Display new warning if needed
        if not self.verify_ssl:
            warning_frame = ctk.CTkFrame(self.login_frame, fg_color="darkred")
            warning_frame.ssl_warning_tag = True
            warning_frame.pack(fill="x", padx=20, pady=(0, 10))
            
            warning_text = ctk.CTkLabel(
                warning_frame, 
                text="⚠️ SSL certificate verification is disabled.\nThis may pose a security risk.",
                text_color="white"
            )
            warning_text.pack(pady=5)
    
    def show_ssl_info(self):
        """Displays information about SSL verification"""
        messagebox.showinfo(
            "SSL Verification", 
            "SSL certificate verification ensures that the connection is secure.\n\n"
            "Disable this option only if you are using a self-signed certificate "
            "or if you encounter connection issues.\n\n"
            "For production, it is recommended to keep this option enabled."
        )
    
    def google_sso_login(self):
        """Handle Google SSO login"""
        try:
            self.log("Starting Google SSO...")
            
            # Check if client ID is configured
            if GOOGLE_CLIENT_ID == "your-google-client-id.apps.googleusercontent.com":
                # Show configuration dialog instead of error
                self.show_sso_config_dialog()
                return
            
            # Create SSO handler
            sso = GoogleSSOHandler(GOOGLE_CLIENT_ID)
            
            # Authenticate
            result = sso.authenticate()
            
            if result["success"]:
                token_data = result["token_data"]
                access_token = token_data.get("access_token")
                
                self.log("Google authentication successful, verifying with backend...")
                
                # Send to backend for verification and JWT creation
                self.authenticate_with_backend(access_token, "google")
            else:
                error = result.get("error", "Unknown error")
                self.log(f"Google SSO failed: {error}")
                messagebox.showerror("Error", f"Google SSO failed: {error}")
                
        except Exception as e:
            self.log(f"SSO error: {str(e)}")
            messagebox.showerror("Error", f"SSO error: {str(e)}")
    
    def show_sso_config_dialog(self):
        """Show dialog to configure SSO or use demo mode"""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("SSO Configuration")
        dialog.geometry("500x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        # Content
        ctk.CTkLabel(dialog, text="Google SSO Configuration Required", font=("Arial", 16, "bold")).pack(pady=15)
        
        ctk.CTkLabel(dialog, text="To use Google SSO, you need to:\n1. Create a project in Google Cloud Console\n2. Enable Google+ API\n3. Create OAuth 2.0 credentials\n4. Add authorized redirect URI: http://localhost:8080/callback", justify="left").pack(pady=10)
        
        ctk.CTkLabel(dialog, text="Or use traditional login (username/password) instead.", font=("Arial", 12, "italic")).pack(pady=10)
        
        btn_frame = ctk.CTkFrame(dialog)
        btn_frame.pack(pady=15)
        
        def close():
            dialog.destroy()
        
        ctk.CTkButton(btn_frame, text="Close", command=close).pack(padx=5)
        
        # Instructions link
        ctk.CTkLabel(dialog, text="See README_SSO.md for detailed setup instructions", text_color="blue").pack(pady=5)
    
    def authenticate_with_backend(self, access_token, provider):
        """Authenticate with backend using SSO credentials"""
        try:
            # Send SSO token to backend
            response = requests.post(
                f"{self.api_url}/auth/sso",
                json={
                    "access_token": access_token,
                    "provider": provider
                },
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self.token = token_data["access_token"]
                self.headers = {"Authorization": f"Bearer {self.token}"}
                
                # Decode token
                token_info = jwt.decode(self.token, options={"verify_signature": False})
                self.current_user = token_info.get("sub", "unknown")
                self.user_role = token_info.get("role", "user")
                self.user_email = token_info.get("email", "")
                
                self.log(f"SSO login successful for {self.current_user} (role: {self.user_role})")
                
                # Remove login frame and show interface
                self.login_frame.destroy()
                self.setup_main_interface()
                
            else:
                error_detail = response.json().get("detail", "Unknown error")
                self.log(f"Backend SSO failed: {error_detail}")
                messagebox.showerror("Error", f"Backend authentication failed: {error_detail}")
                
        except requests.exceptions.RequestException as e:
            self.log(f"Connection error: {str(e)}")
            messagebox.showerror("Error", f"Cannot connect to backend: {str(e)}")
        except Exception as e:
            self.log(f"Backend auth error: {str(e)}")
            messagebox.showerror("Error", f"Authentication error: {str(e)}")
    
    def saml_login(self):
        """SAML SSO login (requires backend support)"""
        messagebox.showinfo(
            "SAML Authentication",
            "SAML authentication requires backend configuration.\n\n"
            "Please contact your administrator for SSO setup.\n\n"
            "Note: SAML typically requires browser-based authentication."
        )
        self.log("SAML login attempted - requires backend configuration")
    
    def authenticate(self):
        """Traditional username/password authentication"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter a username and password")
            return
        
        # Get API URL from input field and save if changed
        new_api_url = self.api_url_entry.get().strip()
        if new_api_url and new_api_url != self.api_url:
            self.api_url = new_api_url
            self._save_api_url(self.api_url)
            self.log(f"API URL updated to: {self.api_url}")
        
        # Get current SSL verification value
        self.verify_ssl = self.ssl_var.get()
        
        self.log(f"Login attempt for {username}...")
        self.log(f"SSL verification: {'enabled' if self.verify_ssl else 'disabled'}")
        
        try:
            response = requests.post(
                f"{self.api_url}/auth/token",
                json={"username": username, "password": password},
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.log(f"Authentication failed: {response.text}")
                messagebox.showerror("Error", f"Authentication failed: {response.status_code}")
                return
            
            token_data = response.json()
            self.token = token_data["access_token"]
            self.headers = {"Authorization": f"Bearer {self.token}"}
            
            # Get user info from token
            token_info = jwt.decode(self.token, options={"verify_signature": False})
            self.current_user = token_info.get("sub", "unknown")
            self.user_role = token_info.get("role", "user")
            self.user_email = token_info.get("email", "")
            
            self.log(f"Login successful for {self.current_user} (role: {self.user_role})")
            
            # Remove login frame
            self.login_frame.destroy()
            
            # Display appropriate interface
            self.setup_main_interface()
                
        except Exception as e:
            self.log(f"Error during authentication: {str(e)}")
            messagebox.showerror("Error", f"Connection error: {str(e)}")
    
    def setup_main_interface(self):
        """Sets up the main interface after login"""
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create tabs
        self.tabs = ctk.CTkTabview(self.content_frame)
        self.tabs.pack(fill="both", expand=True)
        
        # Add tabs based on role
        if self.user_role in ["admin", "master"]:
            self.users_tab = self.tabs.add("Users")
            self.vms_tab = self.tabs.add("Virtual Machines")
            self.assign_tab = self.tabs.add("Assignment")
            self.connect_tab = self.tabs.add("VM Connection")
            
            self.setup_users_tab()
            self.setup_vms_tab()
            self.setup_assign_tab()
            self.setup_connect_tab()
            
            # Load data
            self.load_users()
            self.load_vms()
        else:
            # User interface
            self.connect_tab = self.tabs.add("Your VMs")
            self.setup_user_interface()
        
        # Profile tab for all users
        self.profile_tab = self.tabs.add("Profile")
        self.setup_profile_tab()
        
        # Load assignments for all
        self.load_assignments()
    
    def setup_user_interface(self):
        """Sets up the normal user interface"""
        vm_label = ctk.CTkLabel(self.connect_tab, text="Your virtual machines:", font=("Arial", 14))
        vm_label.pack(pady=(10, 5), anchor="w")
        
        self.vm_list_frame = ctk.CTkFrame(self.connect_tab)
        self.vm_list_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.connect_button = ctk.CTkButton(
            self.connect_tab, 
            text="Connect to VM", 
            command=self.connect_to_vm
        )
        self.connect_button.pack(pady=10)
        
        self.load_user_vms()
    
    def setup_users_tab(self):
        """Sets up the user management tab"""
        list_frame = ctk.CTkFrame(self.users_tab)
        list_frame.pack(fill="both", expand=True, side="left", padx=5, pady=5)
        
        list_label = ctk.CTkLabel(list_frame, text="Users:", font=("Arial", 12))
        list_label.pack(pady=5, anchor="w")
        
        self.users_listbox = ttk.Treeview(list_frame, columns=("id", "username", "role"), show="headings")
        self.users_listbox.heading("id", text="ID")
        self.users_listbox.heading("username", text="Name")
        self.users_listbox.heading("role", text="Role")
        self.users_listbox.column("id", width=50)
        self.users_listbox.column("username", width=150)
        self.users_listbox.column("role", width=100)
        self.users_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        
        action_frame = ctk.CTkFrame(list_frame)
        action_frame.pack(fill="x", pady=5)
        
        reload_btn = ctk.CTkButton(action_frame, text="Refresh", command=self.load_users)
        reload_btn.pack(side="left", padx=5)
        
        delete_btn = ctk.CTkButton(action_frame, text="Delete", fg_color="red", command=self.delete_user)
        delete_btn.pack(side="right", padx=5)
        
        create_frame = ctk.CTkFrame(self.users_tab)
        create_frame.pack(fill="y", side="right", padx=5, pady=5)
        
        create_label = ctk.CTkLabel(create_frame, text="New user:", font=("Arial", 12))
        create_label.pack(pady=5, anchor="w")
        
        username_label = ctk.CTkLabel(create_frame, text="Username:")
        username_label.pack(pady=(10, 0))
        self.new_username = ctk.CTkEntry(create_frame, width=150)
        self.new_username.pack(pady=2)
        
        password_label = ctk.CTkLabel(create_frame, text="Password:")
        password_label.pack(pady=(10, 0))
        self.new_password = ctk.CTkEntry(create_frame, width=150, show="•")
        self.new_password.pack(pady=2)
        
        role_label = ctk.CTkLabel(create_frame, text="Role:")
        role_label.pack(pady=(10, 0))
        self.new_role = ctk.CTkComboBox(create_frame, width=150, values=["user", "admin", "master"])
        self.new_role.pack(pady=2)
        
        create_btn = ctk.CTkButton(create_frame, text="Create user", command=self.create_user)
        create_btn.pack(pady=20)
    
    def setup_vms_tab(self):
        """Sets up the VM management tab"""
        self.vms_treeview = ttk.Treeview(self.vms_tab, columns=("id", "hostname", "ip"), show="headings")
        self.vms_treeview.heading("id", text="ID")
        self.vms_treeview.heading("hostname", text="Hostname")
        self.vms_treeview.heading("ip", text="IP Address")
        self.vms_treeview.column("id", width=50)
        self.vms_treeview.column("hostname", width=150)
        self.vms_treeview.column("ip", width=150)
        self.vms_treeview.pack(fill="both", expand=True, padx=5, pady=5)
        
        refresh_btn = ctk.CTkButton(self.vms_tab, text="Refresh VMs", command=self.load_vms)
        refresh_btn.pack(pady=10)
    
    def setup_assign_tab(self):
        """Sets up the VM-User assignment tab"""
        user_frame = ctk.CTkFrame(self.assign_tab)
        user_frame.pack(fill="x", padx=5, pady=5)
        
        user_label = ctk.CTkLabel(user_frame, text="User:")
        user_label.pack(side="left", padx=5)
        
        self.assign_user = ctk.CTkComboBox(user_frame, width=200, values=[])
        self.assign_user.pack(side="left", padx=5)
        
        vm_frame = ctk.CTkFrame(self.assign_tab)
        vm_frame.pack(fill="x", padx=5, pady=5)
        
        vm_label = ctk.CTkLabel(vm_frame, text="Virtual machine:")
        vm_label.pack(side="left", padx=5)
        
        self.assign_vm = ctk.CTkComboBox(vm_frame, width=200, values=[])
        self.assign_vm.pack(side="left", padx=5)
        
        assign_btn = ctk.CTkButton(self.assign_tab, text="Assign VM to user", command=self.assign_vm_to_user)
        assign_btn.pack(pady=10)
        
        assign_label = ctk.CTkLabel(self.assign_tab, text="Existing assignments:", font=("Arial", 12))
        assign_label.pack(pady=5, anchor="w")
        
        self.assign_treeview = ttk.Treeview(self.assign_tab, columns=("user", "vm"), show="headings")
        self.assign_treeview.heading("user", text="User")
        self.assign_treeview.heading("vm", text="Virtual machine")
        self.assign_treeview.column("user", width=150)
        self.assign_treeview.column("vm", width=150)
        self.assign_treeview.pack(fill="both", expand=True, padx=5, pady=5)
        
        unassign_btn = ctk.CTkButton(self.assign_tab, text="Remove assignment", fg_color="red", command=self.unassign_vm)
        unassign_btn.pack(pady=10)
        
        refresh_assign_btn = ctk.CTkButton(self.assign_tab, text="Refresh Assignments", command=self.load_assignments)
        refresh_assign_btn.pack(pady=5)
    
    def setup_connect_tab(self):
        """Sets up the VM connection tab for admin"""
        vm_label = ctk.CTkLabel(self.connect_tab, text="Your virtual machines:", font=("Arial", 12))
        vm_label.pack(pady=(10, 5), anchor="w")
        
        self.admin_vm_treeview = ttk.Treeview(self.connect_tab, columns=("id", "hostname", "ip"), show="headings")
        self.admin_vm_treeview.heading("id", text="ID")
        self.admin_vm_treeview.heading("hostname", text="Hostname")
        self.admin_vm_treeview.heading("ip", text="IP Address")
        self.admin_vm_treeview.pack(fill="both", expand=True, padx=5, pady=5)
        
        action_frame = ctk.CTkFrame(self.connect_tab)
        action_frame.pack(fill="x", pady=5)
        
        refresh_btn = ctk.CTkButton(action_frame, text="Refresh", command=self.load_admin_vms)
        refresh_btn.pack(side="left", padx=5)
        
        connect_btn = ctk.CTkButton(action_frame, text="Connect", command=self.connect_to_vm)
        connect_btn.pack(side="right", padx=5)
    
    def setup_profile_tab(self):
        """Sets up the profile tab for SSO management"""
        # User info
        info_frame = ctk.CTkFrame(self.profile_tab)
        info_frame.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(info_frame, text="User Information", font=("Arial", 14, "bold")).pack(anchor="w", pady=5)
        ctk.CTkLabel(info_frame, text=f"Username: {self.current_user}").pack(anchor="w")
        ctk.CTkLabel(info_frame, text=f"Email: {self.user_email}").pack(anchor="w")
        ctk.CTkLabel(info_frame, text=f"Role: {self.user_role}").pack(anchor="w")
        
        # SSO management
        sso_frame = ctk.CTkFrame(self.profile_tab)
        sso_frame.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(sso_frame, text="SSO Accounts", font=("Arial", 14, "bold")).pack(anchor="w", pady=5)
        ctk.CTkLabel(sso_frame, text="Link your Google account for passwordless login").pack(anchor="w")
        
        sso_buttons_frame = ctk.CTkFrame(sso_frame)
        sso_buttons_frame.pack(fill="x", pady=10)
        
        link_btn = ctk.CTkButton(
            sso_buttons_frame,
            text="Link Google Account",
            fg_color="#4285F4",
            command=self.link_google_sso
        )
        link_btn.pack(side="left", padx=5, pady=5)
        
        unlink_btn = ctk.CTkButton(
            sso_buttons_frame,
            text="Unlink Google",
            fg_color="red",
            command=self.unlink_google_sso
        )
        unlink_btn.pack(side="left", padx=5, pady=5)
        
        # Logout button
        logout_frame = ctk.CTkFrame(self.profile_tab)
        logout_frame.pack(fill="x", padx=5, pady=20)
        
        logout_btn = ctk.CTkButton(
            logout_frame,
            text="Logout",
            fg_color="red",
            hover_color="#CC0000",
            command=self.logout
        )
        logout_btn.pack(pady=10)
    
    def link_google_sso(self):
        """Link Google SSO to current account"""
        try:
            if GOOGLE_CLIENT_ID == "your-google-client-id.apps.googleusercontent.com":
                self.show_sso_config_dialog()
                return
            
            self.log("Starting Google SSO linking...")
            
            sso = GoogleSSOHandler(GOOGLE_CLIENT_ID)
            result = sso.authenticate()
            
            if not result["success"]:
                messagebox.showerror("Error", result.get("error"))
                return
            
            google_token = result["token_data"]["access_token"]
            
            # Send to backend for linking
            response = requests.post(
                f"{self.api_url}/auth/sso/link",
                headers=self.headers,
                json={
                    "access_token": google_token,
                    "provider": "google"
                },
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                messagebox.showinfo("Success", "Google account linked successfully!")
                self.log("Google SSO linked successfully")
            else:
                error = response.json().get("detail", "Unknown error")
                messagebox.showerror("Error", f"Link failed: {error}")
                
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.log(f"Link error: {str(e)}")
    
    def unlink_google_sso(self):
        """Unlink Google SSO from current account"""
        if not messagebox.askyesno("Confirm", "Are you sure you want to unlink your Google account?"):
            return
        
        try:
            response = requests.post(
                f"{self.api_url}/auth/sso/unlink",
                headers=self.headers,
                json={"provider": "google"},
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                messagebox.showinfo("Success", "Google account unlinked")
                self.log("Google SSO unlinked")
            else:
                error = response.json().get("detail", "Unknown error")
                messagebox.showerror("Error", f"Unlink failed: {error}")
                
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.log(f"Unlink error: {str(e)}")
    
    def logout(self):
        """Logout and return to login screen"""
        if not messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            return
        
        # Clear credentials
        self.token = None
        self.headers = None
        self.current_user = None
        self.user_role = None
        self.user_email = None
        
        # Hide main interface
        self.content_frame.pack_forget()
        
        # Show login frame again
        self.setup_login_frame()
        self.log("User logged out")
    
    def load_users(self):
        """Loads the user list (for admin)"""
        if not self.headers:
            return
            
        self.log("Loading user list...")
        try:
            response = requests.get(f"{self.api_url}/admin/users", headers=self.headers, verify=self.verify_ssl)
            
            if response.status_code != 200:
                self.log(f"Failed to load users: {response.text}")
                return
                
            users = response.json()
            
            # Clear current list
            for item in self.users_listbox.get_children():
                self.users_listbox.delete(item)
                
            # Fill with new data
            for user in users:
                self.users_listbox.insert("", "end", values=(user["id"], user["username"], user["role"]))
                
            # Update assignment combobox
            self.assign_user.configure(values=[f"{user['id']}: {user['username']}" for user in users])
            if users:
                self.assign_user.set(f"{users[0]['id']}: {users[0]['username']}")
                
            self.log(f"{len(users)} users loaded.")
            
        except Exception as e:
            self.log(f"Error loading users: {str(e)}")
    
    def load_vms(self):
        """Loads the VM list"""
        if not self.headers:
            return
            
        self.log("Loading VM list...")
        try:
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl)
            
            if response.status_code != 200:
                self.log(f"Failed to load VMs: {response.text}")
                return
                
            vms = response.json()
            
            # Clear current list
            for item in self.vms_treeview.get_children():
                self.vms_treeview.delete(item)
                
            # Fill with new data
            for vm in vms:
                self.vms_treeview.insert("", "end", values=(vm["id"], vm["hostname"], vm["ip_address"]))
                
            # Update assignment combobox
            self.assign_vm.configure(values=[f"{vm['id']}: {vm['hostname']}" for vm in vms])
            if vms:
                self.assign_vm.set(f"{vms[0]['id']}: {vms[0]['hostname']}")
                
            self.log(f"{len(vms)} VMs loaded.")
            
        except Exception as e:
            self.log(f"Error loading VMs: {str(e)}")
    
    def load_user_vms(self):
        """Loads VMs assigned to current user"""
        if not self.headers:
            return
            
        self.log("Loading your virtual machines...")
        try:
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl)
            
            if response.status_code != 200:
                self.log(f"Failed to load VMs: {response.text}")
                return
                
            vms = response.json()
            
            # Clear current list
            for widget in self.vm_list_frame.winfo_children():
                widget.destroy()
                
            # If no VM
            if not vms:
                no_vm_label = ctk.CTkLabel(self.vm_list_frame, text="No virtual machine assigned")
                no_vm_label.pack(pady=20)
                self.connect_button.configure(state="disabled")
                return
                
            # Create radio buttons for each VM
            self.selected_vm = ctk.StringVar(value=str(vms[0]["id"]))
            for vm in vms:
                vm_radio = ctk.CTkRadioButton(
                    self.vm_list_frame,
                    text=f"{vm['hostname']} ({vm['ip_address']})",
                    variable=self.selected_vm,
                    value=str(vm["id"])
                )
                vm_radio.pack(anchor="w", pady=5)
                
            self.connect_button.configure(state="normal")
            self.log(f"{len(vms)} assigned VMs loaded.")
            
        except Exception as e:
            self.log(f"Error loading VMs: {str(e)}")
    
    def load_admin_vms(self):
        """Loads VMs for admin in connection tab"""
        if not self.headers:
            return
            
        self.log("Loading VMs for connection...")
        try:
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl)
            
            if response.status_code != 200:
                self.log(f"Failed to load VMs: {response.text}")
                return
                
            vms = response.json()
            
            # Clear current list
            for item in self.admin_vm_treeview.get_children():
                self.admin_vm_treeview.delete(item)
                
            # Fill with new data
            for vm in vms:
                self.admin_vm_treeview.insert("", "end", values=(vm["id"], vm["hostname"], vm["ip_address"]))
                
            self.log(f"{len(vms)} VMs loaded for connection.")
            
        except Exception as e:
            self.log(f"Error loading VMs: {str(e)}")
    
    def create_user(self):
        """Creates a new user"""
        username = self.new_username.get()
        password = self.new_password.get()
        role = self.new_role.get()
        
        if not username or not password or not role:
            messagebox.showerror("Error", "Please fill all fields")
            return
            
        self.log(f"Creating user {username} with role {role}...")
        try:
            response = requests.post(
                f"{self.api_url}/auth/register",
                headers=self.headers,
                json={"username": username, "password": password, "role": role},
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.log(f"Failed to create user: {response.text}")
                messagebox.showerror("Error", f"User creation failed: {response.status_code}")
                return
                
            self.log(f"User {username} created successfully")
            messagebox.showinfo("Success", f"User {username} created")
            
            # Clear fields
            self.new_username.delete(0, 'end')
            self.new_password.delete(0, 'end')
            
            # Refresh list
            self.load_users()
            
        except Exception as e:
            self.log(f"Error creating user: {str(e)}")
            messagebox.showerror("Error", f"Creation error: {str(e)}")
    
    def delete_user(self):
        """Deletes a selected user"""
        selected = self.users_listbox.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a user")
            return
            
        user_id = self.users_listbox.item(selected[0])['values'][0]
        username = self.users_listbox.item(selected[0])['values'][1]
        
        if username == self.current_user:
            messagebox.showerror("Error", "You cannot delete your own account")
            return
            
        if not messagebox.askyesno("Confirmation", f"Do you really want to delete user {username}?"):
            return
            
        self.log(f"Deleting user {username} (ID: {user_id})...")
        try:
            response = requests.delete(
                f"{self.api_url}/admin/user/{user_id}",
                headers=self.headers,
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.log(f"Failed to delete user: {response.text}")
                messagebox.showerror("Error", f"Deletion failed: {response.status_code}")
                return
                
            self.log(f"User {username} deleted successfully")
            messagebox.showinfo("Success", f"User {username} deleted")
            
            # Refresh list
            self.load_users()
            
        except Exception as e:
            self.log(f"Error deleting user: {str(e)}")
            messagebox.showerror("Error", f"Deletion error: {str(e)}")
    
    def load_assignments(self):
        """Loads the VM-User assignment list"""
        if not self.headers:
            return

        self.log("Loading existing assignments...")
        try:
            response = requests.get(f"{self.api_url}/vm/assignments", headers=self.headers, verify=self.verify_ssl)

            if response.status_code != 200:
                self.log(f"Failed to load assignments: {response.text}")
                return

            assignments = response.json()

            # Clear current list
            for item in self.assign_treeview.get_children():
                self.assign_treeview.delete(item)

            # Fill with new data
            for assign in assignments:
                assignment_id = f"assign_{assign['user_id']}_{assign['vm_id']}"
                self.assign_treeview.insert(
                    "", "end", 
                    values=(assign["username"], assign["vm_hostname"]), 
                    iid=assignment_id
                )

            self.log(f"{len(assignments)} assignments loaded.")

        except Exception as e:
            self.log(f"Error loading assignments: {str(e)}")
    
    def assign_vm_to_user(self):
        """Assigns a VM to a user"""
        user_selection = self.assign_user.get()
        vm_selection = self.assign_vm.get()
        
        if not user_selection or not vm_selection:
            messagebox.showwarning("Warning", "Please select a user and a VM")
            return
            
        # Extract IDs
        user_id = int(user_selection.split(":")[0])
        vm_id = int(vm_selection.split(":")[0])
        
        self.log(f"Assigning VM {vm_id} to user {user_id}...")
        try:
            response = requests.post(
                f"{self.api_url}/vm/assign",
                headers=self.headers,
                json={"user_id": user_id, "vm_id": vm_id},
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.log(f"Assignment failed: {response.text}")
                messagebox.showerror("Error", f"Assignment failed: {response.status_code}")
                return
                
            result = response.json()
            self.log(f"Assignment successful: {result.get('msg', 'OK')}")
            messagebox.showinfo("Success", "VM assigned successfully")
            
            # Refresh assignments list after success
            self.load_assignments()
            
        except Exception as e:
            self.log(f"Error during assignment: {str(e)}")
            messagebox.showerror("Error", f"Assignment error: {str(e)}")
    
    def unassign_vm(self):
        """Removes a VM-user assignment"""
        selected = self.assign_treeview.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an assignment")
            return
        
        # Get assignment ID from iid
        assignment_id = selected[0]
        username = self.assign_treeview.item(selected[0])['values'][0]
        vm_hostname = self.assign_treeview.item(selected[0])['values'][1]

        if not messagebox.askyesno("Confirmation", f"Do you really want to remove the assignment of {vm_hostname} to {username}?"):
            return

        # Extract user_id and vm_id from assignment ID
        try:
            parts = assignment_id.split('_')
            if len(parts) != 3 or parts[0] != 'assign':
                raise ValueError("Invalid assignment ID format")
            
            user_id = int(parts[1])
            vm_id = int(parts[2])
            
        except (ValueError, IndexError) as e:
            self.log(f"Error extracting IDs: {e}")
            messagebox.showerror("Error", "Cannot determine assignment to delete")
            return

        self.log(f"Attempting to delete assignment ({username} - {vm_hostname})...")
        
        try:
            delete_response = requests.delete(
                f"{self.api_url}/vm/unassign",
                headers=self.headers,
                json={
                    "user_id": user_id,
                    "vm_id": vm_id
                },
                verify=self.verify_ssl
            )
            
            if delete_response.status_code != 200:
                self.log(f"Failed to delete assignment: {delete_response.text}")
                messagebox.showerror("Error", f"Deletion failed: {delete_response.status_code}")
                return

            result = delete_response.json()
            self.log(f"Assignment deleted successfully: {result.get('msg', 'OK')}")
            messagebox.showinfo("Success", "Assignment deleted successfully")
            
            # Refresh assignments list
            self.load_assignments()

        except requests.exceptions.RequestException as e:
            self.log(f"API communication error during deletion: {e}")
            messagebox.showerror("API Error", f"Cannot communicate with API.\nError: {e}")
        except Exception as e:
            self.log(f"Unexpected error deleting assignment: {e}")
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
    
    def connect_to_vm(self):
        """Connects to selected VM"""
        vm_id = None
        
        # Determine which interface is being used
        if hasattr(self, 'selected_vm'):
            # Normal user interface (radio buttons)
            vm_id = self.selected_vm.get()
        else:
            # Admin interface (treeview)
            selected = self.admin_vm_treeview.selection()
            if not selected:
                messagebox.showwarning("Warning", "Please select a VM")
                return
            vm_id = self.admin_vm_treeview.item(selected[0])['values'][0]
        
        if not vm_id:
            messagebox.showwarning("Warning", "Please select a VM")
            return
        
        self.log(f"Preparing connection to VM {vm_id}...")
        
        # Launch pairing and streaming process in a thread
        threading.Thread(target=self.pairing_process, args=(vm_id,), daemon=True).start()
    
    def check_pairing_status(self, ip):
        """Check if pairing already exists with the Sunshine host"""
        try:
            self.log(f"Checking pairing status with {ip}...")
            check_cmd = [MOONLIGHT_EXEC, "list", ip]
            
            # Run with timeout to avoid hanging
            result = subprocess.run(
                check_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # If return code is 0, pairing exists
            if result.returncode == 0:
                self.log("Pairing already exists - skipping pairing process")
                return True
            else:
                self.log("No existing pairing found - pairing required")
                return False
                
        except subprocess.TimeoutExpired:
            self.log("Pairing check timed out - assuming pairing required")
            return False
        except Exception as e:
            self.log(f"Error checking pairing status: {str(e)} - assuming pairing required")
            return False
    
    def pairing_process(self, vm_id):
        """Handles the pairing process with Sunshine"""
        try:
            # Get VM information
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl)
            if response.status_code != 200:
                self.log(f"Failed to retrieve VM info: {response.text}")
                return
                
            vms = response.json()
            
            # Search for VM by ID
            vm = None
            for vm_data in vms:
                if str(vm_data["id"]) == str(vm_id):
                    vm = vm_data
                    break
            
            if not vm:
                self.log(f"VM {vm_id} not found in accessible VM list")
                return
                
            ip = vm["ip_address"]
            
            # Check if pairing already exists
            pairing_exists = self.check_pairing_status(ip)
            
            # Only perform pairing if it doesn't exist
            if not pairing_exists:
                self.log("Starting pairing process...")
                
                # Prepare pairing
                pair_init_response = requests.post(
                    f"{self.api_url}/vm/prepare-pairing",
                    headers=self.headers,
                    json={"vm_id": int(vm_id)},
                    verify=self.verify_ssl
                )
                
                if pair_init_response.status_code != 200:
                    self.log(f"Pairing preparation failed: {pair_init_response.text}")
                    return
                    
                pairing_data = pair_init_response.json()
                pin = pairing_data.get("pin")
                
                if not pin:
                    self.log("PIN not received from server")
                    return
                    
                self.log(f"PIN received: {pin}")
                
                # Launch Moonlight for pairing
                self.log("Launching Moonlight pairing...")
                pair_cmd = [MOONLIGHT_EXEC, "pair", ip, "-pin", pin]
                self.log(f"Command: {' '.join(pair_cmd)}")
                
                moonlight_process = subprocess.Popen(pair_cmd)
                
                # Short delay for Moonlight to start (client side)
                time.sleep(5)
                
                # Send PIN to Sunshine via FastAPI API
                self.log("Sending PIN to Sunshine...")
                pair_response = requests.post(
                    f"{self.api_url}/vm/complete-pairing",
                    headers=self.headers,
                    json={"vm_id": int(vm_id), "pin": pin},
                    verify=self.verify_ssl
                )
                
                if pair_response.status_code != 200:
                    self.log(f"Pairing completion failed: {pair_response.text}")
                    moonlight_process.terminate()
                    return
                
                # Wait for Moonlight process to finish
                return_code = moonlight_process.wait()
                if return_code != 0:
                    self.log(f"Moonlight pairing failed with code {return_code}")
                    return
                    
                self.log("Pairing completed successfully!")
            
            # Launch streaming (whether pairing was just done or already existed)
            self.log("Starting streaming...")
            stream_cmd = [MOONLIGHT_EXEC, "stream", ip, "Desktop"]
            self.log(f"Command: {' '.join(stream_cmd)}")
            
            subprocess.run(stream_cmd, check=True)
            self.log("Streaming session ended")
            
        except Exception as e:
            self.log(f"Error during pairing process: {str(e)}")
    
    def log(self, message):
        """Adds a message to the log area"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.insert("end", f"[{timestamp}] {message}\n")
        self.log_area.see("end")


def main():
    root = ctk.CTk()
    app = EclypseApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()