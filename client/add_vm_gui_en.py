import customtkinter as ctk
from tkinter import messagebox, scrolledtext
import requests
import jwt # To decode token and display connected user
import urllib3 # To disable SSL warnings

# Disable warnings for unverified certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
API_URL = "https://192.168.116.11" # The API listens directly on port 443
# If you use api.caron.fun with a hosts entry, you can put:
# API_URL = "https://api.caron.fun"

class AddVMMangerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Eclypse: Add Virtual Machine")
        self.root.geometry("600x650")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.token = None
        self.headers = None
        self.current_user_role = None
        self.verify_ssl = False # By default, disable SSL verification for self-signed certificates

        # --- Main frame ---
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # --- Log area ---
        self.log_frame = ctk.CTkFrame(self.root)
        self.log_frame.pack(fill="x", padx=10, pady=(0, 10), side="bottom")
        self.log_area = scrolledtext.ScrolledText(self.log_frame, height=5, state='disabled')
        self.log_area.pack(fill="both", expand=True, padx=5, pady=5)
        self.log("'Add VM' application started.")

        # --- Login screen ---
        self.setup_login_frame()

    def log(self, message):
        """Adds a message to the log area."""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_area.configure(state='normal') # Enable editing
        self.log_area.insert("end", f"[{timestamp}] {message}\n")
        self.log_area.see("end") # Scroll to the end
        self.log_area.configure(state='disabled') # Disable editing

    def setup_login_frame(self):
        """Sets up the login interface to obtain admin token."""
        self.login_frame = ctk.CTkFrame(self.main_frame)
        self.login_frame.pack(fill="both", expand=True, padx=20, pady=20)

        title_label = ctk.CTkLabel(self.login_frame, text="Admin API Login", font=("Arial", 20, "bold"))
        title_label.pack(pady=20)

        ctk.CTkLabel(self.login_frame, text="Admin Username:").pack(pady=(10, 0))
        self.username_entry = ctk.CTkEntry(self.login_frame, width=250)
        self.username_entry.pack(pady=5)
        self.username_entry.insert(0, "admin") # Pre-fill with "admin"

        ctk.CTkLabel(self.login_frame, text="Admin Password:").pack(pady=(10, 0))
        self.password_entry = ctk.CTkEntry(self.login_frame, width=250, show="•")
        self.password_entry.pack(pady=5)
        self.password_entry.insert(0, "Test1234") # Pre-fill with "Test1234"

        ssl_frame = ctk.CTkFrame(self.login_frame)
        ssl_frame.pack(pady=10)
        self.ssl_var = ctk.BooleanVar(value=self.verify_ssl) # Use default value
        self.ssl_checkbox = ctk.CTkCheckBox(ssl_frame, text="Verify SSL certificates",
                                            variable=self.ssl_var,
                                            command=self.toggle_ssl_verification)
        self.ssl_checkbox.pack(side="left", padx=5)

        login_button = ctk.CTkButton(self.login_frame, text="Login", command=self.authenticate)
        login_button.pack(pady=20)

        self.show_ssl_warning()

    def toggle_ssl_verification(self):
        """Enables or disables SSL verification."""
        self.verify_ssl = self.ssl_var.get()
        self.log(f"SSL verification {'enabled' if self.verify_ssl else 'disabled'}")
        self.show_ssl_warning()

    def show_ssl_warning(self):
        """Displays a warning if SSL verification is disabled."""
        for widget in self.login_frame.winfo_children():
            if hasattr(widget, 'ssl_warning_tag') and widget.ssl_warning_tag:
                widget.destroy()

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

    def authenticate(self):
        """Attempts to authenticate the admin user."""
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter a username and password.")
            return

        self.log(f"Login attempt for {username}...")
        try:
            response = requests.post(
                f"{API_URL}/auth/token",
                json={"username": username, "password": password},
                verify=self.verify_ssl # Use checkbox value
            )

            if response.status_code != 200:
                self.log(f"Authentication failed: {response.status_code} - {response.text}")
                messagebox.showerror("Authentication Error", f"Failed: {response.status_code}\n{response.json().get('detail', 'Unknown error')}")
                return

            token_data = response.json()
            self.token = token_data["access_token"]
            self.headers = {"Authorization": f"Bearer {self.token}"}

            # Decode token to get role (to ensure it's an admin/master)
            token_info = jwt.decode(self.token, options={"verify_signature": False})
            self.current_user_role = token_info.get("role")

            if self.current_user_role not in ["admin", "master"]:
                messagebox.showerror("Access Denied", "Only users with 'admin' or 'master' role can use this tool.")
                self.log(f"Login successful for {username}, but role ({self.current_user_role}) not authorized.")
                self.token = None
                self.headers = None
                return

            self.log(f"Authentication successful for {username} (role: {self.current_user_role}).")
            messagebox.showinfo("Success", f"Authenticated as {username}.")

            self.login_frame.destroy() # Destroy login frame
            self.setup_add_vm_frame() # Display VM addition interface

        except requests.exceptions.ConnectionError as e:
            self.log(f"API connection error: {e}")
            messagebox.showerror("Connection Error", f"Unable to connect to API at {API_URL}.\nCheck that the server is running and the port is accessible.\n\nError: {e}")
        except Exception as e:
            self.log(f"Unexpected error during authentication: {e}")
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def setup_add_vm_frame(self):
        """Sets up the interface for adding virtual machines."""
        self.add_vm_frame = ctk.CTkFrame(self.main_frame)
        self.add_vm_frame.pack(fill="both", expand=True, padx=20, pady=20)

        title_label = ctk.CTkLabel(self.add_vm_frame, text="Add New Virtual Machine", font=("Arial", 20, "bold"))
        title_label.pack(pady=20)

        # Input fields
        self.entries = {}
        fields = {
            "hostname": "Hostname:",
            "ip_address": "IP Address:",
            "sunshine_user": "Sunshine Username:",
            "sunshine_password": "Sunshine Password:",
        }

        for key, label_text in fields.items():
            frame = ctk.CTkFrame(self.add_vm_frame)
            frame.pack(fill="x", pady=5)
            ctk.CTkLabel(frame, text=label_text, width=150, anchor="w").pack(side="left", padx=5)
            entry = ctk.CTkEntry(frame, width=300)
            entry.pack(side="left", padx=5, fill="x", expand=True)
            self.entries[key] = entry

        add_button = ctk.CTkButton(self.add_vm_frame, text="Add VM", command=self.add_vm)
        add_button.pack(pady=20)

        back_button = ctk.CTkButton(self.add_vm_frame, text="Logout", command=self.logout)
        back_button.pack(pady=5)

    def add_vm(self):
        """Retrieves data and sends request to API to register VM."""
        vm_data = {key: entry.get().strip() for key, entry in self.entries.items()}

        # Simple field validation
        for key, value in vm_data.items():
            if not value:
                messagebox.showerror("Input Error", f"The field '{key.replace('_', ' ').capitalize()}' cannot be empty.")
                return

        self.log(f"Attempting to add VM '{vm_data['hostname']}'...")
        try:
            response = requests.post(
                f"{API_URL}/vm/register",
                headers=self.headers,
                json=vm_data,
                verify=self.verify_ssl # Use checkbox value
            )

            if response.status_code != 200:
                self.log(f"Failed to add VM: {response.status_code} - {response.text}")
                messagebox.showerror("VM Addition Error", f"Failed: {response.status_code}\n{response.json().get('detail', 'Unknown error')}")
                return

            result = response.json()
            self.log(f"VM '{result['hostname']}' successfully added (ID: {result['id']}).")
            messagebox.showinfo("Success", f"VM '{result['hostname']}' successfully added!")

            # Clear fields after successful addition
            for entry in self.entries.values():
                entry.delete(0, ctk.END)

        except requests.exceptions.RequestException as e:
            self.log(f"API communication error: {e}")
            messagebox.showerror("API Error", f"Unable to communicate with API.\nError: {e}")
        except Exception as e:
            self.log(f"Unexpected error while adding VM: {e}")
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def logout(self):
        """Logs out the user and returns to login screen."""
        self.token = None
        self.headers = None
        self.current_user_role = None
        self.add_vm_frame.destroy()
        self.setup_login_frame()
        self.log("Logged out.")

def main():
    root = ctk.CTk()
    app = AddVMMangerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
