import customtkinter as ctk
from tkinter import ttk, messagebox, scrolledtext
import requests
import subprocess
import threading
import time
import urllib3
import jwt
import os # Import of os module for file operations
import socket # For network scanning
from concurrent.futures import ThreadPoolExecutor, as_completed # For parallel scanning
from ipaddress import IPv4Network # For subnet operations

# Try to import zeroconf for mDNS discovery
try:
    from zeroconf import ServiceBrowser, Zeroconf
    ZEROCONF_AVAILABLE = True
except ImportError:
    ZEROCONF_AVAILABLE = False
    print("Warning: zeroconf not available. mDNS discovery disabled. Install with: pip install zeroconf")

# Disable warning for unverified certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Global Configuration ---
# Default API URL if none is saved
DEFAULT_API_URL = "https://n8nua.pp.ua" 
MOONLIGHT_EXEC = "C:/moonlight/Moonlight.exe"
CONFIG_FILE = "client_config.txt" # File name for saving/loading the URL

# Subnet configuration file
SUBNETS_CONFIG_FILE = "subnets.conf"

# Sunshine ports
SUNSHINE_HTTPS_PORT = 47989
SUNSHINE_HTTP_PORT = 47984
SUNSHINE_ALT_PORT = 47990  # Alternative/custom port

# --- mDNS Listener for Sunshine Discovery ---
class SunshineListener:
    """Listener for mDNS service discovery of Sunshine hosts"""
    
    def __init__(self):
        self.discovered_hosts = []
        self.lock = threading.Lock()
    
    def add_service(self, zeroconf, service_type, name):
        """Called when a Sunshine service is discovered"""
        info = zeroconf.get_service_info(service_type, name)
        if info:
            try:
                # Extract IP address
                ip = socket.inet_ntoa(info.addresses[0]) if info.addresses else None
                if ip:
                    # Extract hostname from service name
                    hostname = name.split('.')[0]
                    
                    with self.lock:
                        # Avoid duplicates
                        if not any(h['ip_address'] == ip for h in self.discovered_hosts):
                            self.discovered_hosts.append({
                                'hostname': hostname,
                                'ip_address': ip,
                                'port': info.port if info.port else SUNSHINE_HTTPS_PORT,
                                'method': 'mDNS'
                            })
            except Exception as e:
                print(f"Error processing mDNS service: {e}")
    
    def remove_service(self, zeroconf, service_type, name):
        """Called when a service is removed (not used)"""
        pass
    
    def update_service(self, zeroconf, service_type, name):
        """Called when a service is updated (not used)"""
        pass

class EclypseApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Eclypse Admin - Unified Management Console")
        self.root.geometry("900x700")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.token = None
        self.headers = None
        self.current_user = None
        self.user_role = None
        self.verify_ssl = False  # By default, disable SSL verification
        
        # Load API URL at application startup
        self.api_url = self._load_api_url()
        
        # Main container creation
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
    
    def _load_api_url(self):
        """Loads API URL from configuration file.
        If file doesn't exist or is empty, uses default URL."""
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
        """Sets up the login screen"""
        self.login_frame = ctk.CTkFrame(self.main_frame)
        self.login_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        login_title = ctk.CTkLabel(self.login_frame, text="Eclypse Login", font=("Arial", 18))
        login_title.pack(pady=20)
        
        # --- API URL field (initially hidden) ---
        self.api_url_frame = ctk.CTkFrame(self.login_frame) # New frame to contain URL field
        
        api_url_label = ctk.CTkLabel(self.api_url_frame, text="API URL:")
        api_url_label.pack(pady=(10, 0))
        self.api_url_entry = ctk.CTkEntry(self.api_url_frame, width=300)
        self.api_url_entry.pack(pady=5)
        self.api_url_entry.insert(0, self.api_url) # Pre-fill with loaded URL
        
        # Login fields
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
        
        self.ssl_var = ctk.BooleanVar(value=self.verify_ssl)  # Unchecked by default
        self.ssl_checkbox = ctk.CTkCheckBox(ssl_frame, text="Verify SSL certificates", 
                                            variable=self.ssl_var, 
                                            command=self.toggle_ssl_verification)
        self.ssl_checkbox.pack(side="left", padx=5)
        
        ssl_info_btn = ctk.CTkButton(ssl_frame, text="ℹ️", width=30, 
                                     command=self.show_ssl_info)
        ssl_info_btn.pack(side="left", padx=5)
        
        # --- New checkbox for API URL ---
        self.show_api_url_var = ctk.BooleanVar(value=False) # Unchecked by default
        self.show_api_url_checkbox = ctk.CTkCheckBox(
            self.login_frame, 
            text="Show API URL field", 
            variable=self.show_api_url_var, 
            command=self.toggle_api_url_visibility
        )
        self.show_api_url_checkbox.pack(pady=5) # Place below login fields
        
        # Login button
        login_button = ctk.CTkButton(self.login_frame, text="Login", command=self.authenticate)
        login_button.pack(pady=20)
        
        # Display security warning if SSL verification is disabled
        self.show_ssl_warning()

        # Hide API URL field at startup
        self.toggle_api_url_visibility() 
    
    def toggle_api_url_visibility(self):
        """Shows or hides the API URL input field."""
        if self.show_api_url_var.get():
            self.api_url_frame.pack(pady=5) # Show frame
        else:
            self.api_url_frame.pack_forget() # Hide frame

    def toggle_ssl_verification(self):
        """Enables or disables SSL verification"""
        self.verify_ssl = self.ssl_var.get()
        self.log(f"SSL verification {'enabled' if self.verify_ssl else 'disabled'}")
        self.show_ssl_warning()
        
    def show_ssl_warning(self):
        """Displays a warning if SSL verification is disabled"""
        # Remove existing warning if any
        for widget in self.login_frame.winfo_children():
            # Make sure it's the SSL warning and not other widgets
            if hasattr(widget, 'ssl_warning_tag') and widget.ssl_warning_tag:
                widget.destroy()
                
        # Display new warning if needed
        if not self.verify_ssl:
            warning_frame = ctk.CTkFrame(self.login_frame, fg_color="darkred")
            warning_frame.ssl_warning_tag = True # Tag to identify this widget
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
    
    def setup_admin_interface(self):
        """Sets up the admin interface"""
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create tabs for different admin functions
        self.tabs = ctk.CTkTabview(self.content_frame)
        self.tabs.pack(fill="both", expand=True)
        
        # User management tab
        self.users_tab = self.tabs.add("Users")
        self.setup_users_tab()
        
        # VM management tab
        self.vms_tab = self.tabs.add("Virtual Machines")
        self.setup_vms_tab()
        
        # VM-User assignment tab
        self.assign_tab = self.tabs.add("Assignment")
        self.setup_assign_tab()
        
        # Tab for connecting to VMs (like a normal user)
        self.connect_tab = self.tabs.add("VM Connection")
        self.setup_connect_tab()
        
        # NEW: Add VM tab with Auto-Discovery
        self.add_vm_tab = self.tabs.add("➕ Add VM")
        self.setup_add_vm_tab()
        
        # Load user and VM data
        self.load_users()
        self.load_vms()
    
    def setup_user_interface(self):
        """Sets up the normal user interface"""
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Simple interface for users: just their VM list
        vm_label = ctk.CTkLabel(self.content_frame, text="Your virtual machines:", font=("Arial", 14))
        vm_label.pack(pady=(10, 5), anchor="w")
        
        # VM list
        self.vm_list_frame = ctk.CTkFrame(self.content_frame)
        self.vm_list_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Connect button
        self.connect_button = ctk.CTkButton(self.content_frame, text="Connect to VM", command=self.connect_to_vm)
        self.connect_button.pack(pady=10)
        
        # Refresh user's VM list
        self.load_user_vms()
    
    def setup_users_tab(self):
        """Sets up the user management tab"""
        # User list area
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
        
        # Action buttons
        action_frame = ctk.CTkFrame(list_frame)
        action_frame.pack(fill="x", pady=5)
        
        reload_btn = ctk.CTkButton(action_frame, text="Refresh", command=self.load_users)
        reload_btn.pack(side="left", padx=5)
        
        delete_btn = ctk.CTkButton(action_frame, text="Delete", fg_color="red", command=self.delete_user)
        delete_btn.pack(side="right", padx=5)
        
        # User creation area
        create_frame = ctk.CTkFrame(self.users_tab)
        create_frame.pack(fill="y", side="right", padx=5, pady=5)
        
        create_label = ctk.CTkLabel(create_frame, text="New user:", font=("Arial", 12))
        create_label.pack(pady=5, anchor="w")
        
        # New user fields
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
        
        # Create button
        create_btn = ctk.CTkButton(create_frame, text="Create user", command=self.create_user)
        create_btn.pack(pady=20)
    
    def setup_vms_tab(self):
        """Sets up the VM management tab"""
        # VM list
        self.vms_treeview = ttk.Treeview(self.vms_tab, columns=("id", "hostname", "ip"), show="headings")
        self.vms_treeview.heading("id", text="ID")
        self.vms_treeview.heading("hostname", text="Hostname")
        self.vms_treeview.heading("ip", text="IP Address")
        self.vms_treeview.column("id", width=50)
        self.vms_treeview.column("hostname", width=150)
        self.vms_treeview.column("ip", width=150)
        self.vms_treeview.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Buttons frame
        buttons_frame = ctk.CTkFrame(self.vms_tab)
        buttons_frame.pack(pady=10, fill="x", padx=5)
        
        # Refresh button
        refresh_btn = ctk.CTkButton(buttons_frame, text="Refresh VMs", command=self.load_vms)
        refresh_btn.pack(side="left", padx=5)
        
        # Delete button
        delete_btn = ctk.CTkButton(
            buttons_frame, 
            text="Delete VM", 
            command=self.delete_vm,
            fg_color="red",
            hover_color="darkred"
        )
        delete_btn.pack(side="right", padx=5)
    
    def setup_assign_tab(self):
        """Sets up the VM-User assignment tab"""
        # User section
        user_frame = ctk.CTkFrame(self.assign_tab)
        user_frame.pack(fill="x", padx=5, pady=5)
        
        user_label = ctk.CTkLabel(user_frame, text="User:")
        user_label.pack(side="left", padx=5)
        
        self.assign_user = ctk.CTkComboBox(user_frame, width=200, values=[])
        self.assign_user.pack(side="left", padx=5)
        
        # VM section
        vm_frame = ctk.CTkFrame(self.assign_tab)
        vm_frame.pack(fill="x", padx=5, pady=5)
        
        vm_label = ctk.CTkLabel(vm_frame, text="Virtual machine:")
        vm_label.pack(side="left", padx=5)
        
        self.assign_vm = ctk.CTkComboBox(vm_frame, width=200, values=[])
        self.assign_vm.pack(side="left", padx=5)
        
        # Assignment button
        assign_btn = ctk.CTkButton(self.assign_tab, text="Assign VM to user", command=self.assign_vm_to_user)
        assign_btn.pack(pady=10)
        
        # Existing assignments list
        assign_label = ctk.CTkLabel(self.assign_tab, text="Existing assignments:", font=("Arial", 12))
        assign_label.pack(pady=5, anchor="w")
        
        self.assign_treeview = ttk.Treeview(self.assign_tab, columns=("user", "vm"), show="headings")
        self.assign_treeview.heading("user", text="User")
        self.assign_treeview.heading("vm", text="Virtual machine")
        self.assign_treeview.column("user", width=150)
        self.assign_treeview.column("vm", width=150)
        self.assign_treeview.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Button to remove an assignment
        unassign_btn = ctk.CTkButton(self.assign_tab, text="Remove assignment", fg_color="red", command=self.unassign_vm)
        unassign_btn.pack(pady=10)

        # Refresh assignments button
        refresh_assign_btn = ctk.CTkButton(self.assign_tab, text="Refresh Assignments", command=self.load_assignments)
        refresh_assign_btn.pack(pady=5)
    
    def setup_connect_tab(self):
        """Sets up the VM connection tab (for admin)"""
        # Accessible VM list
        vm_label = ctk.CTkLabel(self.connect_tab, text="Your virtual machines:", font=("Arial", 12))
        vm_label.pack(pady=(10, 5), anchor="w")
        
        self.admin_vm_treeview = ttk.Treeview(self.connect_tab, columns=("id", "hostname", "ip"), show="headings")
        self.admin_vm_treeview.heading("id", text="ID")
        self.admin_vm_treeview.heading("hostname", text="Hostname")
        self.admin_vm_treeview.heading("ip", text="IP Address")
        self.admin_vm_treeview.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Action buttons
        action_frame = ctk.CTkFrame(self.connect_tab)
        action_frame.pack(fill="x", pady=5)
        
        refresh_btn = ctk.CTkButton(action_frame, text="Refresh", command=self.load_admin_vms)
        refresh_btn.pack(side="left", padx=5)
        
        connect_btn = ctk.CTkButton(action_frame, text="Connect", command=self.connect_to_vm)
        connect_btn.pack(side="right", padx=5)
    
    def authenticate(self):
        """Authenticates the user and loads the appropriate interface"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter a username and password")
            return
        
        # Get API URL from input field and save if changed
        new_api_url = self.api_url_entry.get().strip()
        if new_api_url and new_api_url != self.api_url:
            self.api_url = new_api_url
            self._save_api_url(self.api_url) # Save new URL
            self.log(f"API URL updated to: {self.api_url}")
        
        # Get current SSL verification value
        self.verify_ssl = self.ssl_var.get()
        
        self.log(f"Login attempt for {username}...")
        self.log(f"SSL verification: {'enabled' if self.verify_ssl else 'disabled'}")
        
        try:
            response = requests.post(
                f"{self.api_url}/auth/token", # Use self.api_url
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
            
            self.log(f"Login successful for {self.current_user} (role: {self.user_role})")
            
            # Remove login frame
            self.login_frame.destroy()
            
            # Display appropriate interface based on role
            if self.user_role in ["admin", "master"]:
                self.setup_admin_interface()
            else:
                self.setup_user_interface()
                
        except Exception as e:
            self.log(f"Error during authentication: {str(e)}")
            messagebox.showerror("Error", f"Connection error: {str(e)}")
    
    def load_users(self):
        """Loads the user list (for admin)"""
        if not self.headers:
            return
            
        self.log("Loading user list...")
        try:
            response = requests.get(f"{self.api_url}/admin/users", headers=self.headers, verify=self.verify_ssl) # Use self.api_url
            
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
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl) # Use self.api_url
            
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
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl) # Use self.api_url
            
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
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl) # Use self.api_url
            
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
                f"{self.api_url}/auth/register", # Use self.api_url
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
                f"{self.api_url}/admin/user/{user_id}", # Use self.api_url
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
        """Loads the VM-User assignment list (optimized version)"""
        if not self.headers:
            return

        self.log("Loading existing assignments...")
        try:
            response = requests.get(f"{self.api_url}/vm/assignments", headers=self.headers, verify=self.verify_ssl) # Use self.api_url

            if response.status_code != 200:
                self.log(f"Failed to load assignments: {response.text}")
                return

            assignments = response.json()

            # Clear current list
            for item in self.assign_treeview.get_children():
                self.assign_treeview.delete(item)

            # Fill with new data
            for assign in assignments:
                # Create unique ID for assignment
                assignment_id = f"assign_{assign['user_id']}_{assign['vm_id']}"
                self.assign_treeview.insert(
                    "", "end", 
                    values=(assign["username"], assign["vm_hostname"]), 
                    iid=assignment_id  # Explicitly set iid
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
                f"{self.api_url}/vm/assign", # Use self.api_url
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
        """Removes a VM-user assignment (functional version)"""
        selected = self.assign_treeview.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an assignment")
            return
        
        # Get assignment ID from iid
        assignment_id = selected[0]  # iid is directly the item ID
        username = self.assign_treeview.item(selected[0])['values'][0]
        vm_hostname = self.assign_treeview.item(selected[0])['values'][1]

        if not messagebox.askyesno("Confirmation", f"Do you really want to remove the assignment of {vm_hostname} to {username}?"):
            return

        # Extract user_id and vm_id from assignment ID
        try:
            # ID is in format "assign_userId_vmId"
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
                f"{self.api_url}/vm/unassign", # Use self.api_url
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
        """Connects to selected VM (normal user AND admin)"""
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
            # Try to list apps - if successful, pairing exists
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
    
    def delete_vm(self):
        """Deletes selected VM from database"""
        selected = self.vms_treeview.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a VM to delete")
            return
        
        # Get VM details from selection
        vm_id = self.vms_treeview.item(selected[0])['values'][0]
        vm_hostname = self.vms_treeview.item(selected[0])['values'][1]
        vm_ip = self.vms_treeview.item(selected[0])['values'][2]
        
        # Confirmation dialog
        if not messagebox.askyesno(
            "Confirm Deletion",
            f"Are you sure you want to delete this VM?\n\n"
            f"Hostname: {vm_hostname}\n"
            f"IP: {vm_ip}\n\n"
            f"This action cannot be undone."
        ):
            return
        
        self.log(f"Attempting to delete VM {vm_id} ({vm_hostname})...")
        try:
            response = requests.delete(
                f"{self.api_url}/vm/delete/{vm_id}",
                headers=self.headers,
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.log(f"Failed to delete VM: {response.status_code} - {response.text}")
                messagebox.showerror(
                    "Deletion Error",
                    f"Failed to delete VM\n"
                    f"Status: {response.status_code}\n"
                    f"Error: {response.json().get('detail', 'Unknown error')}"
                )
                return
            
            result = response.json()
            self.log(f"VM deleted successfully: {result.get('msg', 'OK')}")
            messagebox.showinfo("Success", f"VM '{vm_hostname}' deleted successfully!")
            
            # Refresh VM list
            self.load_vms()
            
        except requests.exceptions.RequestException as e:
            self.log(f"API communication error during deletion: {e}")
            messagebox.showerror("API Error", f"Unable to communicate with API.\nError: {e}")
        except Exception as e:
            self.log(f"Unexpected error deleting VM: {e}")
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
    
    def pairing_process(self, vm_id):
        """Handles the pairing process with Sunshine"""
        try:
            # Get VM information
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl)
            if response.status_code != 200:
                self.log(f"Failed to retrieve VM info: {response.text}")
                return
                
            vms = response.json()
            
            # Search for VM by ID (convert to string for comparison)
            vm = None
            for vm_data in vms:
                if str(vm_data["id"]) == str(vm_id):
                    vm = vm_data
                    break
            
            if not vm:
                self.log(f"VM {vm_id} not found in accessible VM list")
                self.log(f"Available VMs: {[v['id'] for v in vms]}")
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
            stream_cmd = [MOONLIGHT_EXEC, "stream", ip, "Desktop", "--resolution", "1920x1080", "--fps", "60"]
            self.log(f"Command: {' '.join(stream_cmd)}")
            
            subprocess.run(stream_cmd, check=True)
            self.log("Streaming session ended")
            
        except Exception as e:
            self.log(f"Error during pairing process: {str(e)}")
    
    # ===== AUTO-DISCOVERY AND SUBNET CONFIGURATION METHODS =====
    
    def setup_add_vm_tab(self):
        """Setup Add VM tab with manual entry and auto-discovery"""
        # Title
        title_label = ctk.CTkLabel(self.add_vm_tab, text="Add Virtual Machine", 
                                   font=("Arial", 16, "bold"))
        title_label.pack(pady=10)
        
        # Manual entry fields
        fields_frame = ctk.CTkFrame(self.add_vm_tab)
        fields_frame.pack(padx=20, pady=10, fill="x")
        
        # Entry fields dictionary
        self.add_vm_entries = {}
        
        fields = [
            ("hostname", "Hostname:"),
            ("ip_address", "IP Address:"),
            ("sunshine_user", "Sunshine User:"),
            ("sunshine_password", "Sunshine Password:")
        ]
        
        for field, label_text in fields:
            label = ctk.CTkLabel(fields_frame, text=label_text)
            label.pack(pady=(10, 0))
            
            if field == "sunshine_password":
                entry = ctk.CTkEntry(fields_frame, width=300, show="•")
            else:
                entry = ctk.CTkEntry(fields_frame, width=300)
            
            entry.pack(pady=5)
            self.add_vm_entries[field] = entry
        
        # Auto-Discovery button
        scan_button = ctk.CTkButton(
            self.add_vm_tab,
            text="🔍 Auto-Discover Sunshine Hosts",
            command=self.scan_network,
            fg_color="#1f6aa5",
            hover_color="#144870",
            width=250,
            height=40
        )
        scan_button.pack(pady=15)
        
        # Config editor button
        config_button = ctk.CTkButton(
            self.add_vm_tab,
            text="⚙️ Configure Subnets",
            command=self.open_subnet_config,
            fg_color="#555555",
            hover_color="#444444",
            width=180
        )
        config_button.pack(pady=5)
        
        # Separator
        separator_label = ctk.CTkLabel(self.add_vm_tab, text="─── OR ───", 
                                      text_color="gray")
        separator_label.pack(pady=10)
        
        # Add VM button
        add_button = ctk.CTkButton(
            self.add_vm_tab,
            text="Add VM Manually",
            command=self.add_vm_manual,
            width=200
        )
        add_button.pack(pady=10)
    
    def add_vm_manual(self):
        """Add VM from manual entry fields"""
        vm_data = {key: entry.get().strip() for key, entry in self.add_vm_entries.items()}
        
        # Validation
        for key, value in vm_data.items():
            if not value:
                messagebox.showerror("Input Error", 
                                   f"The field '{key.replace('_', ' ').capitalize()}' cannot be empty.")
                return
        
        self.log(f"Attempting to add VM '{vm_data['hostname']}'...")
        try:
            response = requests.post(
                f"{self.api_url}/vm/register",
                headers=self.headers,
                json=vm_data,
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.log(f"Failed to add VM: {response.status_code} - {response.text}")
                messagebox.showerror("VM Addition Error", 
                                   f"Failed: {response.status_code}\\n{response.json().get('detail', 'Unknown error')}")
                return
            
            result = response.json()
            self.log(f"VM '{result['hostname']}' successfully added (ID: {result['id']}).")
            messagebox.showinfo("Success", f"VM '{result['hostname']}' successfully added!")
            
            # Clear fields
            for entry in self.add_vm_entries.values():
                entry.delete(0, ctk.END)
            
            # Refresh VM list in other tabs
            self.load_vms()
            
        except requests.exceptions.RequestException as e:
            self.log(f"API communication error: {e}")
            messagebox.showerror("API Error", f"Unable to communicate with API.\\nError: {e}")
        except Exception as e:
            self.log(f"Unexpected error while adding VM: {e}")
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
    
    def load_subnets_config(self):
        """Load subnet list from configuration file"""
        import os
        
        # Get config file path relative to script location
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(script_dir, SUBNETS_CONFIG_FILE)
        
        subnets = []
        
        # If config doesn't exist, create default one
        if not os.path.exists(config_path):
            self.log(f"Config file not found, creating default: {config_path}")
            self._create_default_subnet_config(config_path)
        
        try:
            with open(config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if line and not line.startswith('#'):
                        try:
                            # Validate subnet
                            network = IPv4Network(line, strict=False)
                            subnets.append(str(network))
                        except ValueError as e:
                            self.log(f"Invalid subnet in config: {line} - {e}")
            
            if not subnets:
                # Fallback to local network
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                local_network = IPv4Network(f"{local_ip}/24", strict=False)
                subnets.append(str(local_network))
                self.log("No valid subnets in config, using local network")
            
            self.log(f"Loaded {len(subnets)} subnet(s) from config")
            return subnets
            
        except Exception as e:
            self.log(f"Error reading subnet config: {e}")
            # Fallback to local network
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                local_network = IPv4Network(f"{local_ip}/24", strict=False)
                return [str(local_network)]
            except:
                return ['192.168.1.0/24']  # Ultimate fallback
    
    def _create_default_subnet_config(self, config_path):
        """Create default subnet configuration file"""
        try:
            # Detect local network
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            local_network = IPv4Network(f"{local_ip}/24", strict=False)
            
            default_content = f'''# Subnet Configuration File for Sunshine Discovery
# Add one subnet per line in CIDR notation
# Lines starting with # are comments
# Example: 192.168.1.0/24

# Auto-detected local network
{local_network}

# Add your additional subnets below:
# 192.168.2.0/24
# 10.0.0.0/24
'''
            with open(config_path, 'w') as f:
                f.write(default_content)
            
            self.log(f"Created default config with subnet: {local_network}")
        except Exception as e:
            self.log(f"Error creating default config: {e}")
    
    def open_subnet_config(self):
        """Open subnet configuration editor"""
        import os
        import tkinter as tk
        
        config_window = ctk.CTkToplevel(self.root)
        config_window.title("Subnet Configuration")
        config_window.geometry("500x400")
        config_window.transient(self.root)
        config_window.grab_set()
        
        # Title
        title = ctk.CTkLabel(config_window, text="⚙️ Configure Subnets", 
                            font=("Arial", 18, "bold"))
        title.pack(pady=15)
        
        # Instructions
        instructions = ctk.CTkLabel(
            config_window,
            text="Enter subnets to scan (one per line, CIDR notation)\\nExample: 192.168.1.0/24",
            font=("Arial", 10),
            text_color="gray"
        )
        instructions.pack(pady=5)
        
        # Text editor
        text_frame = ctk.CTkFrame(config_window)
        text_frame.pack(pady=10, padx=20, fill="both", expand=True)
        
        text_editor = tk.Text(text_frame, height=15, width=50, 
                             bg="#2b2b2b", fg="white", 
                             insertbackground="white",
                             font=("Consolas", 10))
        text_editor.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Load current config
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(script_dir, SUBNETS_CONFIG_FILE)
        
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                text_editor.insert('1.0', f.read())
        
        # Buttons
        button_frame = ctk.CTkFrame(config_window)
        button_frame.pack(pady=10)
        
        def save_config():
            content = text_editor.get('1.0', 'end-1c')
            try:
                with open(config_path, 'w') as f:
                    f.write(content)
                self.log("Subnet configuration saved")
                messagebox.showinfo("Success", "Subnet configuration saved successfully!")
                config_window.destroy()
            except Exception as e:
                self.log(f"Error saving config: {e}")
                messagebox.showerror("Error", f"Failed to save config: {e}")
        
        save_btn = ctk.CTkButton(button_frame, text="Save", command=save_config)
        save_btn.pack(side="left", padx=5)
        
        cancel_btn = ctk.CTkButton(button_frame, text="Cancel", 
                                   command=config_window.destroy)
        cancel_btn.pack(side="left", padx=5)
    
    def scan_network(self):
        """Open scan dialog and start network discovery"""
        self.log("Starting network scan for Sunshine hosts...")
        
        # Create scan dialog
        scan_window = ctk.CTkToplevel(self.root)
        scan_window.title("Network Scan")
        scan_window.geometry("700x600")
        scan_window.transient(self.root)
        scan_window.grab_set()
        
        # Title
        title = ctk.CTkLabel(scan_window, text="🔍 Discovering Sunshine Hosts", 
                            font=("Arial", 18, "bold"))
        title.pack(pady=15)
        
        # Status label
        self.scan_status_label = ctk.CTkLabel(scan_window, text="Initializing scan...", 
                                             font=("Arial", 12))
        self.scan_status_label.pack(pady=5)
        
        # Progress bar
        self.scan_progress = ctk.CTkProgressBar(scan_window, width=600)
        self.scan_progress.pack(pady=10)
        self.scan_progress.set(0)
        
        # Results frame (scrollable)
        results_label = ctk.CTkLabel(scan_window, text="Discovered Hosts:", 
                                     font=("Arial", 14, "bold"))
        results_label.pack(pady=(10, 5))
        
        self.scan_results_frame = ctk.CTkScrollableFrame(scan_window, width=650, height=300)
        self.scan_results_frame.pack(pady=5, padx=20, fill="both", expand=True)
        
        # Close button
        close_btn = ctk.CTkButton(scan_window, text="Close", 
                                 command=scan_window.destroy)
        close_btn.pack(pady=10)
        
        # Start scan in background thread
        scan_thread = threading.Thread(
            target=self._perform_scan,
            args=(scan_window,),
            daemon=True
        )
        scan_thread.start()
    
    def _perform_scan(self, scan_window):
        """Perform the actual network scan"""
        discovered = []
        
        # Update status
        self.root.after(0, lambda: self.scan_status_label.configure(
            text="Scanning using mDNS..."))
        self.root.after(0, lambda: self.scan_progress.set(0.2))
        
        # Load configured subnets
        configured_subnets = self.load_subnets_config()
        self.root.after(0, lambda: self.scan_status_label.configure(
            text=f"Loaded {len(configured_subnets)} subnet(s) from config"))
        
        # METHOD 1: mDNS Discovery
        if ZEROCONF_AVAILABLE:
            try:
                self.log("Attempting mDNS discovery...")
                zeroconf = Zeroconf()
                listener = SunshineListener()
                
                # Browse for Sunshine services (_nvstream._tcp is used by Sunshine)
                browser = ServiceBrowser(zeroconf, "_nvstream._tcp.local.", listener)
                
                # Wait for discovery (5 seconds)
                time.sleep(5)
                
                discovered = listener.discovered_hosts.copy()
                
                zeroconf.close()
                
                self.log(f"mDNS discovery found {len(discovered)} host(s)")
                self.root.after(0, lambda: self.scan_progress.set(0.5))
                
            except Exception as e:
                self.log(f"mDNS discovery failed: {e}")
        else:
            self.log("Zeroconf not available, skipping mDNS discovery")
        
        # METHOD 2: Port Scanning Fallback (if no hosts found or zeroconf unavailable)
        if len(discovered) == 0:
            self.root.after(0, lambda: self.scan_status_label.configure(
                text="No mDNS hosts found. Starting port scan..."))
            self.root.after(0, lambda: self.scan_progress.set(0.6))
            
            self.log("Starting port scan on configured subnets...")
            port_scan_results = self._port_scan_network(configured_subnets)
            discovered.extend(port_scan_results)
            self.log(f"Port scan found {len(port_scan_results)} additional host(s)")
        
        # Update UI with results
        self.root.after(0, lambda: self.scan_progress.set(1.0))
        
        if discovered:
            self.root.after(0, lambda: self.scan_status_label.configure(
                text=f"✅ Found {len(discovered)} Sunshine host(s)", 
                text_color="green"))
            
            for host in discovered:
                self.root.after(0, lambda h=host: self._create_host_card(h))
        else:
            self.root.after(0, lambda: self.scan_status_label.configure(
                text="❌ No Sunshine hosts found on network", 
                text_color="orange"))
            self.log("No Sunshine hosts discovered")
    
    def _port_scan_network(self, subnets=None):
        """Scan configured subnets for Sunshine ports"""
        discovered = []
        
        if subnets is None:
            subnets = self.load_subnets_config()
        
        try:
            total_hosts = 0
            all_ips = []
            
            # Collect all IPs from all subnets
            for subnet_str in subnets:
                network = IPv4Network(subnet_str, strict=False)
                hosts = list(network.hosts())
                total_hosts += len(hosts)
                all_ips.extend([(str(ip), subnet_str) for ip in hosts])
                self.log(f"Subnet {subnet_str}: {len(hosts)} hosts")
            
            self.log(f"Scanning {total_hosts} total hosts across {len(subnets)} subnet(s)...")
            
            # Update status with subnet info
            self.root.after(0, lambda: self.scan_status_label.configure(
                text=f"Scanning {total_hosts} hosts in {len(subnets)} subnet(s)..."))
            
            # Scan in parallel using thread pool
            with ThreadPoolExecutor(max_workers=100) as executor:
                future_to_ip = {executor.submit(self._check_sunshine_port, ip, subnet): (ip, subnet) 
                              for ip, subnet in all_ips}
                
                completed = 0
                for future in as_completed(future_to_ip):
                    result = future.result()
                    if result:
                        discovered.append(result)
                    
                    # Update progress
                    completed += 1
                    if completed % 10 == 0:  # Update every 10 hosts
                        progress = 0.6 + (0.3 * completed / total_hosts)
                        self.root.after(0, lambda p=progress: self.scan_progress.set(p))
            
            return discovered
            
        except Exception as e:
            self.log(f"Port scan error: {e}")
            return []
    
    def _check_sunshine_port(self, ip, subnet=None):
        """Check if a specific IP has Sunshine running"""
        ports = [SUNSHINE_HTTPS_PORT, SUNSHINE_HTTP_PORT, SUNSHINE_ALT_PORT]
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)  # Increased timeout for VPN connections
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    # Port is open, likely Sunshine
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = f"host-{ip.split('.')[-1]}"
                    
                    return {
                        'hostname': hostname,
                        'ip_address': ip,
                        'port': port,
                        'method': f'Port Scan ({subnet})' if subnet else 'Port Scan'
                    }
            except:
                pass
        
        return None
    
    def _create_host_card(self, host):
        """Create a card UI element for a discovered host"""
        # Create card frame
        card = ctk.CTkFrame(self.scan_results_frame, fg_color=("gray75", "gray25"))
        card.pack(fill="x", pady=5, padx=5)
        
        # Left side - Host info
        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        
        hostname_label = ctk.CTkLabel(
            info_frame,
            text=f"🖥️  {host.get('hostname', 'Unknown')}",
            font=("Arial", 13, "bold"),
            anchor="w"
        )
        hostname_label.pack(anchor="w")
        
        ip_label = ctk.CTkLabel(
            info_frame,
            text=f"📍 IP: {host['ip_address']}  |  Port: {host.get('port', 'N/A')}  |  Method: {host.get('method', 'Unknown')}",
            font=("Arial", 10),
            anchor="w",
            text_color="gray"
        )
        ip_label.pack(anchor="w")
        
        # Right side - Add button
        add_btn = ctk.CTkButton(
            card,
            text="➕ Add to Database",
            command=lambda h=host: self._quick_add_host(h),
            width=150
        )
        add_btn.pack(side="right", padx=10, pady=10)
    
    def _quick_add_host(self, host):
        """Auto-fill form with discovered host information"""
        # Create credentials input dialog
        cred_window = ctk.CTkToplevel(self.root)
        cred_window.title("Enter Sunshine Credentials")
        cred_window.geometry("400x280")
        cred_window.transient(self.root)
        cred_window.grab_set()
        
        # Title
        title = ctk.CTkLabel(
            cred_window, 
            text=f"🔐 Sunshine Credentials", 
            font=("Arial", 16, "bold")
        )
        title.pack(pady=15)
        
        # Info label
        info_label = ctk.CTkLabel(
            cred_window,
            text=f"Host: {host.get('hostname', 'Unknown')}\\nIP: {host['ip_address']}\\n\\nEnter Sunshine login credentials:",
            font=("Arial", 10)
        )
        info_label.pack(pady=5)
        
        # Username field
        username_label = ctk.CTkLabel(cred_window, text="Sunshine Username:")
        username_label.pack(pady=(10, 0))
        username_entry = ctk.CTkEntry(cred_window, width=250)
        username_entry.pack(pady=5)
        username_entry.insert(0, "admin")  # Default suggestion
        username_entry.focus()
        
        # Password field
        password_label = ctk.CTkLabel(cred_window, text="Sunshine Password:")
        password_label.pack(pady=(10, 0))
        password_entry = ctk.CTkEntry(cred_window, width=250, show="•")
        password_entry.pack(pady=5)
        
        # Result storage
        credentials = {'confirmed': False}
        
        def on_confirm():
            sunshine_user = username_entry.get().strip()
            sunshine_pass = password_entry.get().strip()
            
            if not sunshine_user or not sunshine_pass:
                messagebox.showwarning(
                    "Missing Credentials",
                    "Please enter both username and password"
                )
                return
            
            credentials['sunshine_user'] = sunshine_user
            credentials['sunshine_password'] = sunshine_pass
            credentials['confirmed'] = True
            cred_window.destroy()
        
        def on_cancel():
            credentials['confirmed'] = False
            cred_window.destroy()
        
        # Buttons
        button_frame = ctk.CTkFrame(cred_window)
        button_frame.pack(pady=15)
        
        confirm_btn = ctk.CTkButton(button_frame, text="OK", command=on_confirm, width=100)
        confirm_btn.pack(side="left", padx=5)
        
        cancel_btn = ctk.CTkButton(button_frame, text="Cancel", command=on_cancel, width=100)
        cancel_btn.pack(side="left", padx=5)
        
        # Handle Enter key
        password_entry.bind('<Return>', lambda e: on_confirm())
        
        # Wait for window to close
        self.root.wait_window(cred_window)
        
        # If user confirmed, auto-fill the form
        if credentials.get('confirmed'):
            # Auto-fill hostname
            self.add_vm_entries['hostname'].delete(0, ctk.END)
            self.add_vm_entries['hostname'].insert(0, host.get('hostname', ''))
            
            # Auto-fill IP address
            self.add_vm_entries['ip_address'].delete(0, ctk.END)
            self.add_vm_entries['ip_address'].insert(0, host['ip_address'])
            
            # Auto-fill Sunshine credentials
            self.add_vm_entries['sunshine_user'].delete(0, ctk.END)
            self.add_vm_entries['sunshine_user'].insert(0, credentials['sunshine_user'])
            
            self.add_vm_entries['sunshine_password'].delete(0, ctk.END)
            self.add_vm_entries['sunshine_password'].insert(0, credentials['sunshine_password'])
            
            # Log action
            self.log(f"Auto-filled form with host: {host['ip_address']} and credentials")
            
            # Notify user
            messagebox.showinfo(
                "Host Ready",
                f"All fields have been filled!\\n\\n"
                f"Hostname: {host.get('hostname', 'Unknown')}\\n"
                f"IP: {host['ip_address']}\\n"
                f"User: {credentials['sunshine_user']}\\n\\n"
                f"Click 'Add VM Manually' to register."
            )
            
            # Switch to Add VM tab
            self.tabs.set("➕ Add VM")
        else:
            self.log("Host selection cancelled by user")
    
    def log(self, message):
        """Adds a message to the log area"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.insert("end", f"[{timestamp}] {message}\n")
        self.log_area.see("end")  # Scroll to end

def main():
    root = ctk.CTk()
    app = EclypseApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
