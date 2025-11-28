import customtkinter as ctk
from tkinter import ttk, messagebox, scrolledtext
import requests
import subprocess
import threading
import time
import urllib3
import jwt
import os 
import uuid 
import binascii 
# Библиотеки cryptography удалены, так как используется PIN-аутентификация
# from cryptography.hazmat.primitives import hashes 
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
# from cryptography.hazmat.backends import default_backend 

# ----------------------------------------------------------------------
# --- КОНФИГУРАЦИЯ ---
# ----------------------------------------------------------------------

# Отключить предупреждение для самоподписанных сертификатов (SSL Verification Disabled)
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_API_URL = "https://n8nua.pp.ua"
MOONLIGHT_EXEC = "C:/moonlight/Moonlight.exe"
CONFIG_FILE = "client_config.txt"

# !!! ВАЖНО: УЧЕТНЫЕ ДАННЫЕ SUNSHINE API !!!
# Логин и пароль, которые используются для входа в веб-интерфейс Sunshine (порт 47990).
SUNSHINE_API_USER = "ваше_имя_пользователя_sunshine" 
SUNSHINE_API_PASS = "ваш_пароль_sunshine"
# ----------------------------------------------------------------------


class EclypseApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Eclypse Client")
        self.root.geometry("800x600")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        self.token = None
        self.headers = None
        self.current_user = None
        self.user_role = None
        self.verify_ssl = False
        
        self.api_url = self._load_api_url()
        
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.setup_login_frame()
        
        self.content_frame = ctk.CTkFrame(self.main_frame)
        
        self.log_frame = ctk.CTkFrame(self.root)
        self.log_frame.pack(fill="x", padx=10, pady=(0, 10), side="bottom")
        
        self.log_area = scrolledtext.ScrolledText(self.log_frame, height=6)
        self.log_area.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.log("Application démarrée.")
        self.log(f"URL de l'API actuelle: {self.api_url}")
    
    def _load_api_url(self):
        """Charge l'URL de l'API depuis un fichier de configuration."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    url = f.readline().strip()
                    if url:
                        return url
            except Exception as e:
                self.log(f"Erreur lors de la lecture du fichier de configuration: {str(e)}")
        return DEFAULT_API_URL

    def _save_api_url(self, url):
        """Sauvegarde l'URL de l'API dans un fichier de configuration."""
        try:
            with open(CONFIG_FILE, 'w') as f:
                f.write(url)
            self.log(f"URL de l'API sauvegardée: {url}")
        except Exception as e:
            self.log(f"Erreur lors de la sauvegarde de l'URL de l'API: {str(e)}")
    
    def setup_login_frame(self):
        """Configure l'écran de connexion"""
        self.login_frame = ctk.CTkFrame(self.main_frame)
        self.login_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        login_title = ctk.CTkLabel(self.login_frame, text="Connexion Eclypse", font=("Arial", 18))
        login_title.pack(pady=20)
        
        self.api_url_frame = ctk.CTkFrame(self.login_frame) 
        
        api_url_label = ctk.CTkLabel(self.api_url_frame, text="URL de l'API:")
        api_url_label.pack(pady=(10, 0))
        self.api_url_entry = ctk.CTkEntry(self.api_url_frame, width=300)
        self.api_url_entry.pack(pady=5)
        self.api_url_entry.insert(0, self.api_url) 
        
        username_label = ctk.CTkLabel(self.login_frame, text="Nom d'utilisateur:")
        username_label.pack(pady=(10, 0))
        self.username_entry = ctk.CTkEntry(self.login_frame, width=200)
        self.username_entry.pack(pady=5)
        
        password_label = ctk.CTkLabel(self.login_frame, text="Mot de passe:")
        password_label.pack(pady=(10, 0))
        self.password_entry = ctk.CTkEntry(self.login_frame, width=200, show="•")
        self.password_entry.pack(pady=5)
        
        ssl_frame = ctk.CTkFrame(self.login_frame)
        ssl_frame.pack(pady=10)
        
        self.ssl_var = ctk.BooleanVar(value=self.verify_ssl) 
        self.ssl_checkbox = ctk.CTkCheckBox(ssl_frame, text="Vérifier les certificats SSL", 
                                                 variable=self.ssl_var, 
                                                 command=self.toggle_ssl_verification)
        self.ssl_checkbox.pack(side="left", padx=5)
        
        ssl_info_btn = ctk.CTkButton(ssl_frame, text="ℹ️", width=30, 
                                          command=self.show_ssl_info)
        ssl_info_btn.pack(side="left", padx=5)
        
        self.show_api_url_var = ctk.BooleanVar(value=False) 
        self.show_api_url_checkbox = ctk.CTkCheckBox(
            self.login_frame, 
            text="Afficher le champ URL de l'API", 
            variable=self.show_api_url_var, 
            command=self.toggle_api_url_visibility
        )
        self.show_api_url_checkbox.pack(pady=5) 
        
        login_button = ctk.CTkButton(self.login_frame, text="Se connecter", command=self.authenticate)
        login_button.pack(pady=20)
        
        self.show_ssl_warning()

        self.toggle_api_url_visibility() 
    
    def toggle_api_url_visibility(self):
        """Affiche ou masque le champ de saisie de l'URL de l'API."""
        if self.show_api_url_var.get():
            self.api_url_frame.pack(pady=5) 
        else:
            self.api_url_frame.pack_forget() 

    def toggle_ssl_verification(self):
        """Active ou désactive la vérification SSL"""
        self.verify_ssl = self.ssl_var.get()
        self.log(f"Vérification SSL {'activée' if self.verify_ssl else 'désactivée'}")
        self.show_ssl_warning()
        
    def show_ssl_warning(self):
        """Affiche un avertissement si la vérification SSL est désactivée"""
        for widget in self.login_frame.winfo_children():
            if hasattr(widget, 'ssl_warning_tag') and widget.ssl_warning_tag:
                widget.destroy()
                
        if not self.verify_ssl:
            warning_frame = ctk.CTkFrame(self.login_frame, fg_color="darkred")
            warning_frame.ssl_warning_tag = True 
            warning_frame.pack(fill="x", padx=20, pady=(0, 10))
            
            warning_text = ctk.CTkLabel(
                warning_frame, 
                text="⚠️ La vérification des certificats SSL est désactivée.\nCela peut présenter un risque de sécurité.",
                text_color="white"
            )
            warning_text.pack(pady=5)
    
    def show_ssl_info(self):
        """Affiche des informations sur la vérification SSL"""
        messagebox.showinfo(
            "Vérification SSL", 
            "La vérification des certificats SSL garantit que la connexion est sécurisée.\n\n"
            "Désactivez cette option uniquement si vous utilisez un certificat auto-signé "
            "ou si vous rencontrez des problèmes de connexion.\n\n"
            "Pour la production, il est recommandé de garder cette option activée."
        )
    
    def setup_admin_interface(self):
        """Configure l'interface administrateur"""
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.tabs = ctk.CTkTabview(self.content_frame)
        self.tabs.pack(fill="both", expand=True)
        
        self.users_tab = self.tabs.add("Utilisateurs")
        self.setup_users_tab()
        
        self.vms_tab = self.tabs.add("Machines virtuelles")
        self.setup_vms_tab()
        
        self.assign_tab = self.tabs.add("Assignation")
        self.setup_assign_tab()
        
        self.connect_tab = self.tabs.add("Connexion VM")
        self.setup_connect_tab()
        
        self.load_users()
        self.load_vms()
    
    def setup_user_interface(self):
        """Configure l'interface utilisateur normal"""
        self.content_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        vm_label = ctk.CTkLabel(self.content_frame, text="Vos machines virtuelles:", font=("Arial", 14))
        vm_label.pack(pady=(10, 5), anchor="w")
        
        self.vm_list_frame = ctk.CTkFrame(self.content_frame)
        self.vm_list_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.connect_button = ctk.CTkButton(self.content_frame, text="Se connecter à la VM", command=self.connect_to_vm)
        self.connect_button.pack(pady=10)
        
        self.load_user_vms()
    
    def setup_users_tab(self):
        """Configure l'onglet de gestion des utilisateurs"""
        list_frame = ctk.CTkFrame(self.users_tab)
        list_frame.pack(fill="both", expand=True, side="left", padx=5, pady=5)
        
        list_label = ctk.CTkLabel(list_frame, text="Utilisateurs:", font=("Arial", 12))
        list_label.pack(pady=5, anchor="w")
        
        self.users_listbox = ttk.Treeview(list_frame, columns=("id", "username", "role"), show="headings")
        self.users_listbox.heading("id", text="ID")
        self.users_listbox.heading("username", text="Nom")
        self.users_listbox.heading("role", text="Rôle")
        self.users_listbox.column("id", width=50)
        self.users_listbox.column("username", width=150)
        self.users_listbox.column("role", width=100)
        self.users_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        
        action_frame = ctk.CTkFrame(list_frame)
        action_frame.pack(fill="x", pady=5)
        
        reload_btn = ctk.CTkButton(action_frame, text="Actualiser", command=self.load_users)
        reload_btn.pack(side="left", padx=5)
        
        delete_btn = ctk.CTkButton(action_frame, text="Supprimer", fg_color="red", command=self.delete_user)
        delete_btn.pack(side="right", padx=5)
        
        create_frame = ctk.CTkFrame(self.users_tab)
        create_frame.pack(fill="y", side="right", padx=5, pady=5)
        
        create_label = ctk.CTkLabel(create_frame, text="Nouvel utilisateur:", font=("Arial", 12))
        create_label.pack(pady=5, anchor="w")
        
        username_label = ctk.CTkLabel(create_frame, text="Nom d'utilisateur:")
        username_label.pack(pady=(10, 0))
        self.new_username = ctk.CTkEntry(create_frame, width=150)
        self.new_username.pack(pady=2)
        
        password_label = ctk.CTkLabel(create_frame, text="Mot de passe:")
        password_label.pack(pady=(10, 0))
        self.new_password = ctk.CTkEntry(create_frame, width=150, show="•")
        self.new_password.pack(pady=2)
        
        role_label = ctk.CTkLabel(create_frame, text="Rôle:")
        role_label.pack(pady=(10, 0))
        self.new_role = ctk.CTkComboBox(create_frame, width=150, values=["user", "admin", "master"])
        self.new_role.pack(pady=2)
        
        create_btn = ctk.CTkButton(create_frame, text="Créer utilisateur", command=self.create_user)
        create_btn.pack(pady=20)
    
    def setup_vms_tab(self):
        """Configure l'onglet de gestion des VMs"""
        self.vms_treeview = ttk.Treeview(self.vms_tab, columns=("id", "hostname", "ip"), show="headings")
        self.vms_treeview.heading("id", text="ID")
        self.vms_treeview.heading("hostname", text="Nom d'hôte")
        self.vms_treeview.heading("ip", text="Adresse IP")
        self.vms_treeview.column("id", width=50)
        self.vms_treeview.column("hostname", width=150)
        self.vms_treeview.column("ip", width=150)
        self.vms_treeview.pack(fill="both", expand=True, padx=5, pady=5)
        
        refresh_btn = ctk.CTkButton(self.vms_tab, text="Actualiser VMs", command=self.load_vms)
        refresh_btn.pack(pady=10)
    
    def setup_assign_tab(self):
        """Configure l'onglet d'assignation VM-Utilisateur"""
        user_frame = ctk.CTkFrame(self.assign_tab)
        user_frame.pack(fill="x", padx=5, pady=5)
        
        user_label = ctk.CTkLabel(user_frame, text="Utilisateur:")
        user_label.pack(side="left", padx=5)
        
        self.assign_user = ctk.CTkComboBox(user_frame, width=200, values=[])
        self.assign_user.pack(side="left", padx=5)
        
        vm_frame = ctk.CTkFrame(self.assign_tab)
        vm_frame.pack(fill="x", padx=5, pady=5)
        
        vm_label = ctk.CTkLabel(vm_frame, text="Machine virtuelle:")
        vm_label.pack(side="left", padx=5)
        
        self.assign_vm = ctk.CTkComboBox(vm_frame, width=200, values=[])
        self.assign_vm.pack(side="left", padx=5)
        
        assign_btn = ctk.CTkButton(self.assign_tab, text="Assigner VM à l'utilisateur", command=self.assign_vm_to_user)
        assign_btn.pack(pady=10)
        
        assign_label = ctk.CTkLabel(self.assign_tab, text="Assignations existantes:", font=("Arial", 12))
        assign_label.pack(pady=5, anchor="w")
        
        self.assign_treeview = ttk.Treeview(self.assign_tab, columns=("user", "vm"), show="headings")
        self.assign_treeview.heading("user", text="Utilisateur")
        self.assign_treeview.heading("vm", text="Machine virtuelle")
        self.assign_treeview.column("user", width=150)
        self.assign_treeview.column("vm", width=150)
        self.assign_treeview.pack(fill="both", expand=True, padx=5, pady=5)
        
        unassign_btn = ctk.CTkButton(self.assign_tab, text="Supprimer assignation", fg_color="red", command=self.unassign_vm)
        unassign_btn.pack(pady=10)

        refresh_assign_btn = ctk.CTkButton(self.assign_tab, text="Actualiser Assignations", command=self.load_assignments)
        refresh_assign_btn.pack(pady=5)
    
    def setup_connect_tab(self):
        """Configure l'onglet de connexion aux VMs (pour admin)"""
        vm_label = ctk.CTkLabel(self.connect_tab, text="Vos machines virtuelles:", font=("Arial", 12))
        vm_label.pack(pady=(10, 5), anchor="w")
        
        self.admin_vm_treeview = ttk.Treeview(self.connect_tab, columns=("id", "hostname", "ip"), show="headings")
        self.admin_vm_treeview.heading("id", text="ID")
        self.admin_vm_treeview.heading("hostname", text="Nom d'hôte")
        self.admin_vm_treeview.heading("ip", text="Adresse IP")
        self.admin_vm_treeview.pack(fill="both", expand=True, padx=5, pady=5)
        
        action_frame = ctk.CTkFrame(self.connect_tab)
        action_frame.pack(fill="x", pady=5)
        
        refresh_btn = ctk.CTkButton(action_frame, text="Actualiser", command=self.load_admin_vms)
        refresh_btn.pack(side="left", padx=5)
        
        connect_btn = ctk.CTkButton(action_frame, text="Se connecter", command=self.connect_to_vm)
        connect_btn.pack(side="right", padx=5)
    
    def authenticate(self):
        """Authentifie l'utilisateur et charge l'interface appropriée"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Erreur", "Veuillez entrer un nom d'utilisateur et un mot de passe")
            return
        
        new_api_url = self.api_url_entry.get().strip()
        if new_api_url and new_api_url != self.api_url:
            self.api_url = new_api_url
            self._save_api_url(self.api_url) 
            self.log(f"URL de l'API mise à jour vers: {self.api_url}")
        
        self.verify_ssl = self.ssl_var.get()
        
        self.log(f"Tentative de connexion pour {username}...")
        self.log(f"Vérification SSL: {'activée' if self.verify_ssl else 'désactivée'}")
        
        try:
            response = requests.post(
                f"{self.api_url}/auth/token", 
                json={"username": username, "password": password},
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.log(f"Échec d'authentification: {response.text}")
                messagebox.showerror("Erreur", f"Authentification échouée: {response.status_code}")
                return
            
            token_data = response.json()
            self.token = token_data["access_token"]
            self.headers = {"Authorization": f"Bearer {self.token}"}
            
            token_info = jwt.decode(self.token, options={"verify_signature": False})
            self.current_user = token_info.get("sub", "unknown")
            self.user_role = token_info.get("role", "user")
            
            self.log(f"Connexion réussie pour {self.current_user} (rôle: {self.user_role})")
            
            self.login_frame.destroy()
            
            if self.user_role in ["admin", "master"]:
                self.setup_admin_interface()
            else:
                self.setup_user_interface()
                
        except Exception as e:
            self.log(f"Erreur lors de l'authentification: {str(e)}")
            messagebox.showerror("Erreur", f"Erreur de connexion: {str(e)}")
    
    def load_users(self):
        """Charge la liste des utilisateurs (pour admin)"""
        if not self.headers: return
            
        self.log("Chargement de la liste des utilisateurs...")
        try:
            response = requests.get(f"{self.api_url}/admin/users", headers=self.headers, verify=self.verify_ssl)
            
            if response.status_code != 200:
                self.log(f"Échec du chargement des utilisateurs: {response.text}")
                return
                
            users = response.json()
            
            for item in self.users_listbox.get_children():
                self.users_listbox.delete(item)
                
            for user in users:
                self.users_listbox.insert("", "end", values=(user["id"], user["username"], user["role"]))
                
            self.assign_user.configure(values=[f"{user['id']}: {user['username']}" for user in users])
            if users:
                self.assign_user.set(f"{users[0]['id']}: {users[0]['username']}")
                
            self.log(f"{len(users)} utilisateurs chargés.")
            
        except Exception as e:
            self.log(f"Erreur lors du chargement des utilisateurs: {str(e)}")
    
    def load_vms(self):
        """Charge la liste des VMs"""
        if not self.headers: return
            
        self.log("Chargement de la liste des VMs...")
        try:
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl)
            
            if response.status_code != 200:
                self.log(f"Échec du chargement des VMs: {response.text}")
                return
                
            vms = response.json()
            
            for item in self.vms_treeview.get_children():
                self.vms_treeview.delete(item)
                
            for vm in vms:
                self.vms_treeview.insert("", "end", values=(vm["id"], vm["hostname"], vm["ip_address"]))
                
            self.assign_vm.configure(values=[f"{vm['id']}: {vm['hostname']}" for vm in vms])
            if vms:
                self.assign_vm.set(f"{vms[0]['id']}: {vms[0]['hostname']}")
                
            self.log(f"{len(vms)} VMs chargées.")
            
        except Exception as e:
            self.log(f"Erreur lors du chargement des VMs: {str(e)}")
    
    def load_user_vms(self):
        """Charge les VMs assignées à l'utilisateur actuel"""
        if not self.headers: return
            
        self.log("Chargement de vos machines virtuelles...")
        try:
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl)
            
            if response.status_code != 200:
                self.log(f"Échec du chargement des VMs: {response.text}")
                return
                
            vms = response.json()
            
            for widget in self.vm_list_frame.winfo_children():
                widget.destroy()
                
            if not vms:
                no_vm_label = ctk.CTkLabel(self.vm_list_frame, text="Aucune machine virtuelle assignée")
                no_vm_label.pack(pady=20)
                self.connect_button.configure(state="disabled")
                return
                
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
            self.log(f"{len(vms)} VMs assignées chargées.")
            
        except Exception as e:
            self.log(f"Erreur lors du chargement des VMs: {str(e)}")
    
    def load_admin_vms(self):
        """Charge les VMs pour l'admin dans l'onglet de connexion"""
        if not self.headers: return
            
        self.log("Chargement des VMs pour connexion...")
        try:
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl)
            
            if response.status_code != 200:
                self.log(f"Échec du chargement des VMs: {response.text}")
                return
                
            vms = response.json()
            
            for item in self.admin_vm_treeview.get_children():
                self.admin_vm_treeview.delete(item)
                
            for vm in vms:
                self.admin_vm_treeview.insert("", "end", values=(vm["id"], vm["hostname"], vm["ip_address"]))
                
            self.log(f"{len(vms)} VMs chargées pour connexion.")
            
        except Exception as e:
            self.log(f"Erreur lors du chargement des VMs: {str(e)}")
    
    def create_user(self):
        """Crée un nouvel utilisateur"""
        username = self.new_username.get()
        password = self.new_password.get()
        role = self.new_role.get()
        
        if not username or not password or not role:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs")
            return
            
        self.log(f"Création de l'utilisateur {username} avec rôle {role}...")
        try:
            response = requests.post(
                f"{self.api_url}/auth/register", 
                headers=self.headers,
                json={"username": username, "password": password, "role": role},
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.log(f"Échec de création de l'utilisateur: {response.text}")
                messagebox.showerror("Erreur", f"Création utilisateur échouée: {response.status_code}")
                return
                
            self.log(f"Utilisateur {username} créé avec succès")
            messagebox.showinfo("Succès", f"Utilisateur {username} créé")
            
            self.new_username.delete(0, 'end')
            self.new_password.delete(0, 'end')
            
            self.load_users()
            
        except Exception as e:
            self.log(f"Erreur lors de la création de l'utilisateur: {str(e)}")
            messagebox.showerror("Erreur", f"Erreur de création: {str(e)}")
    
    def delete_user(self):
        """Supprime un utilisateur sélectionné"""
        selected = self.users_listbox.selection()
        if not selected:
            messagebox.showwarning("Avertissement", "Veuillez sélectionner un utilisateur")
            return
            
        user_id = self.users_listbox.item(selected[0])['values'][0]
        username = self.users_listbox.item(selected[0])['values'][1]
        
        if username == self.current_user:
            messagebox.showerror("Erreur", "Vous ne pouvez pas supprimer votre propre compte")
            return
            
        if not messagebox.askyesno("Confirmation", f"Voulez-vous vraiment supprimer l'utilisateur {username}?"):
            return
            
        self.log(f"Suppression de l'utilisateur {username} (ID: {user_id})...")
        try:
            response = requests.delete(
                f"{self.api_url}/admin/user/{user_id}", 
                headers=self.headers,
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.log(f"Échec de suppression de l'utilisateur: {response.text}")
                messagebox.showerror("Erreur", f"Suppression échouée: {response.status_code}")
                return
                
            self.log(f"Utilisateur {username} supprimé avec succès")
            messagebox.showinfo("Succès", f"Utilisateur {username} supprimé")
            
            self.load_users()
            
        except Exception as e:
            self.log(f"Erreur lors de la suppression de l'utilisateur: {str(e)}")
            messagebox.showerror("Erreur", f"Erreur de suppression: {str(e)}")
    
    def load_assignments(self):
        """Charge la liste des assignations VM-Utilisateur"""
        if not self.headers: return

        self.log("Chargement des assignations existantes...")
        try:
            response = requests.get(f"{self.api_url}/vm/assignments", headers=self.headers, verify=self.verify_ssl)

            if response.status_code != 200:
                self.log(f"Échec du chargement des assignations: {response.text}")
                return

            assignments = response.json()

            for item in self.assign_treeview.get_children():
                self.assign_treeview.delete(item)

            for assign in assignments:
                assignment_id = f"assign_{assign['user_id']}_{assign['vm_id']}"
                self.assign_treeview.insert(
                    "", "end", 
                    values=(assign["username"], assign["vm_hostname"]), 
                    iid=assignment_id  
                )

            self.log(f"{len(assignments)} assignations chargées.")

        except Exception as e:
            self.log(f"Erreur lors du chargement des assignations: {str(e)}")
    
    def assign_vm_to_user(self):
        """Assigne une VM à un utilisateur"""
        user_selection = self.assign_user.get()
        vm_selection = self.assign_vm.get()
        
        if not user_selection or not vm_selection:
            messagebox.showwarning("Avertissement", "Veuillez sélectionner un utilisateur et une VM")
            return
            
        user_id = int(user_selection.split(":")[0])
        vm_id = int(vm_selection.split(":")[0])
        
        self.log(f"Assignation de la VM {vm_id} à l'utilisateur {user_id}...")
        try:
            response = requests.post(
                f"{self.api_url}/vm/assign", 
                headers=self.headers,
                json={"user_id": user_id, "vm_id": vm_id},
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                self.log(f"Échec d'assignation: {response.text}")
                messagebox.showerror("Erreur", f"Assignation échouée: {response.status_code}")
                return
                
            result = response.json()
            self.log(f"Assignation réussie: {result.get('msg', 'OK')}")
            messagebox.showinfo("Succès", "VM assignée avec succès")
            
            self.load_assignments()
            
        except Exception as e:
            self.log(f"Erreur lors de l'assignation: {str(e)}")
            messagebox.showerror("Erreur", f"Erreur d'assignation: {str(e)}")
    
    def unassign_vm(self):
        """Supprime une assignation VM-utilisateur"""
        selected = self.assign_treeview.selection()
        if not selected:
            messagebox.showwarning("Avertissement", "Veuillez sélectionner une assignation")
            return
        
        assignment_id = selected[0]
        username = self.assign_treeview.item(selected[0])['values'][0]
        vm_hostname = self.assign_treeview.item(selected[0])['values'][1]

        if not messagebox.askyesno("Confirmation", f"Voulez-vous vraiment supprimer l'assignation de {vm_hostname} à {username}?"):
            return

        try:
            parts = assignment_id.split('_')
            if len(parts) != 3 or parts[0] != 'assign':
                raise ValueError("Format d'ID d'assignation invalide")
            
            user_id = int(parts[1])
            vm_id = int(parts[2])
            
        except (ValueError, IndexError) as e:
            self.log(f"Erreur lors de l'extraction des IDs: {e}")
            messagebox.showerror("Erreur", "Impossible de déterminer l'assignation à supprimer")
            return

        self.log(f"Tentative de suppression de l'assignation ({username} - {vm_hostname})...")
        
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
                self.log(f"Échec de suppression de l'assignation: {delete_response.text}")
                messagebox.showerror("Erreur", f"Suppression échouée: {delete_response.status_code}")
                return

            result = delete_response.json()
            self.log(f"Assignation supprimée avec succès: {result.get('msg', 'OK')}")
            messagebox.showinfo("Succès", "Assignation supprimée avec succès")
            
            self.load_assignments()

        except requests.exceptions.RequestException as e:
            self.log(f"Erreur de communication avec l'API lors de la suppression: {e}")
            messagebox.showerror("Erreur API", f"Impossible de communiquer avec l'API.\nErreur: {e}")
        except Exception as e:
            self.log(f"Erreur inattendue lors de la suppression de l'assignation: {e}")
            messagebox.showerror("Erreur", f"Une erreur inattendue est survenue: {e}")
    
    def connect_to_vm(self):
        """Se connecte à la VM sélectionnée"""
        vm_id = None
        
        if hasattr(self, 'selected_vm'):
            vm_id = self.selected_vm.get()
        else:
            selected = self.admin_vm_treeview.selection()
            if not selected:
                messagebox.showwarning("Avertissement", "Veuillez sélectionner une VM")
                return
            vm_id = self.admin_vm_treeview.item(selected[0])['values'][0]
        
        if not vm_id:
            messagebox.showwarning("Avertissement", "Veuillez sélectionner une VM")
            return
        
        self.log(f"Préparation de la connexion à la VM {vm_id}...")
        
        threading.Thread(target=self.pairing_process, args=(vm_id,), daemon=True).start()
    
    # --- ВОССТАНОВЛЕННЫЙ МЕТОД СОПРЯЖЕНИЯ ЧЕРЕЗ PIN-КОД С АВТОМАТИЗАЦИЕЙ ---
    def pairing_process(self, vm_id):
        """
        Генерирует PIN-код через Eclypse Server, запускает Moonlight pair,
        АВТОМАТИЧЕСКИ подтверждает PIN через Sunshine API, и начинает стриминг.
        """
        try:
            # 1. Получить информацию о VM (IP)
            response = requests.get(f"{self.api_url}/vm/list", headers=self.headers, verify=self.verify_ssl)
            response.raise_for_status()
                
            vms = response.json()
            vm = next((v for v in vms if str(v["id"]) == str(vm_id)), None)
            
            if not vm:
                self.log(f"VM {vm_id} non trouvée.")
                return
                
            ip = vm["ip_address"]
            
            # 2. Шаг 1: Запросить PIN у Eclypse Server
            self.log("Préparation du pairing: demande de PIN au serveur Eclypse...")
            
            pair_init_response = requests.post(
                f"{self.api_url}/vm/prepare-pairing",
                headers=self.headers,
                json={"vm_id": int(vm_id)},
                verify=self.verify_ssl
            )
            
            pair_init_response.raise_for_status()
            
            pairing_data = pair_init_response.json()
            pin = pairing_data.get("pin")
            
            if not pin:
                self.log("❌ PIN non reçu du serveur Eclypse")
                return
                
            self.log(f"PIN reçu: {pin}")
            
            # 3. Шаг 2: Запустить Moonlight для сопряжения с PIN
            self.log("Lancement du pairing Moonlight...")
            pair_cmd = [MOONLIGHT_EXEC, "pair", ip, "-pin", pin]
            self.log(f"Commande: {' '.join(pair_cmd)}")
            
            # ИЗМЕНЕНИЕ 1: Добавление encoding='utf-8' и errors='ignore'
            moonlight_process = subprocess.Popen(pair_cmd, encoding='utf-8', errors='ignore')
            time.sleep(2) # Небольшая задержка, чтобы Moonlight начал процесс сопряжения
            
            # ----------------------------------------------------------------------
            # --- ШАГ 3.5: АВТОМАТИЧЕСКОЕ ПОДТВЕРЖДЕНИЕ PIN-КОДА ЧЕРЕЗ SUNSHINE API ---
            # ----------------------------------------------------------------------
            
            sunshine_api_url = f"https://{ip}:47990/api/pin"
            
            self.log(f"API Sunshine: Попытка автоматического подтверждения PIN-кода ({pin})...")
            
            sunshine_pair_response = requests.post(
                url=sunshine_api_url,
                # Используем учетные данные API Sunshine
                auth=requests.auth.HTTPBasicAuth(SUNSHINE_API_USER, SUNSHINE_API_PASS), 
                verify=False, # Отключение проверки SSL для Sunshine
                json={"pin": pin, "name": f"Eclypse Client {os.environ.get('COMPUTERNAME', 'Auto')}"}
            )
            
            # Проверяем, был ли запрос успешным (ожидается 200)
            sunshine_pair_response.raise_for_status() 
            
            self.log("✅ PIN успешно отправлен и подтвержден через Sunshine API.")
            
            # ----------------------------------------------------------------------
            
            # 4. Шаг 4: Отправить PIN обратно Eclypse Server для формального завершения
            self.log("Envoi du PIN à Eclypse pour finaliser le pairing...")
            pair_complete_response = requests.post(
                f"{self.api_url}/vm/complete-pairing",
                headers=self.headers,
                json={"vm_id": int(vm_id), "pin": pin},
                verify=self.verify_ssl
            )
            
            pair_complete_response.raise_for_status()

            # Дождаться завершения Moonlight-процесса и проверить результат
            return_code = moonlight_process.wait()
            if return_code != 0:
                 self.log(f"❌ Échec du pairing Moonlight avec code {return_code}")
                 return
                
            self.log("Pairing complété avec succès!")
            
            # 5. Запуск Streaming
            self.log("Démarrage du streaming...")
            stream_cmd = [MOONLIGHT_EXEC, "stream", ip, "Desktop"]
            self.log(f"Commande: {' '.join(stream_cmd)}")
            
            subprocess.run(stream_cmd, check=True)
            self.log("Session de streaming terminée")
            
        except requests.exceptions.HTTPError as e:
             if e.response.status_code == 401:
                 error_msg = "401 AUTHENTICATION FAILED: Проверьте SUNSHINE_API_USER/PASS."
             else:
                 error_msg = f"HTTP Error {e.response.status_code}: {e.response.text}"
                 
             self.log(f"❌ Erreur lors de l'envoi du PIN à Sunshine: {error_msg}")
             # Если Moonlight был запущен, пытаемся его остановить
             if 'moonlight_process' in locals() and moonlight_process.poll() is None:
                 moonlight_process.terminate()
             messagebox.showerror("Erreur Sunshine API", f"Échec de l'autentification/PIN: {error_msg}")
        except Exception as e:
            self.log(f"❌ Erreur lors du processus de pairing: {str(e)}")
            messagebox.showerror("Erreur Pairing", f"Erreur inattendue: {str(e)}")
            
    
    def log(self, message):
        """Ajoute un message dans la zone de logs"""
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