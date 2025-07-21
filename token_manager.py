import json
import os
from datetime import datetime, timedelta
from azure.identity import ClientSecretCredential

class TokenManager:
    def __init__(self, config):
        self.config = config
        self.tokens_file = "access_tokens.json"
        self.tokens = {}
        self.load_tokens()
    
    def load_tokens(self):
        """Load tokens from file if they exist"""
        if os.path.exists(self.tokens_file):
            try:
                with open(self.tokens_file, 'r') as f:
                    self.tokens = json.load(f)
            except:
                self.tokens = {}
    
    def save_tokens(self):
        """Save tokens to file"""
        with open(self.tokens_file, 'w') as f:
            json.dump(self.tokens, f)
    
    def get_new_tokens(self):
        """Get new tokens using Azure credentials"""
        try:
            tenant_id = self.config.tenant_id
            client_id = self.config.client_id
            client_secret = self.config.client_secret
            
            if not all([tenant_id, client_id, client_secret]):
                print("==== TOKEN ERROR ====")
                print("Missing Azure credentials in config.json")
                print("Add tenant_id, client_id, and client_secret to config.json")
                print("------")
                return False
            
            credential = ClientSecretCredential(tenant_id, client_id, client_secret)
            
            self.tokens = {
                "arm": credential.get_token("https://management.azure.com/.default").token,
                "graph": credential.get_token("https://graph.microsoft.com/.default").token,
                "expires_at": (datetime.now() + timedelta(hours=1)).isoformat()
            }
            
            self.save_tokens()
            print("==== TOKENS REFRESHED ====")
            print("New access tokens obtained and saved")
            print("------")
            return True
            
        except Exception as e:
            print("==== TOKEN ERROR ====")
            print(f"Failed to get new tokens: {e}")
            print("------")
            return False
    
    def are_tokens_expired(self):
        """Check if tokens are expired or missing"""
        if not self.tokens or 'expires_at' not in self.tokens:
            return True
        
        try:
            expires_at = datetime.fromisoformat(self.tokens['expires_at'])
            return datetime.now() >= expires_at
        except:
            return True
    
    def get_tokens(self):
        """Get valid tokens, refreshing if needed"""
        if self.are_tokens_expired():
            if not self.get_new_tokens():
                return None
        return self.tokens 