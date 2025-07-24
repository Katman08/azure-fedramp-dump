#!/usr/bin/env python3
"""
Helper utilities for Security Policy Printer v3

This module provides shared utilities including formatting functions,
configuration management, token management, and API client functionality.
"""

import json
import os
import sys
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional


class Tee:
    """Tee output to both console and file"""
    def __init__(self, *files):
        self.files = files
    
    def write(self, obj):
        for f in self.files:
            f.write(obj)
            f.flush()
    
    def flush(self):
        for f in self.files:
            f.flush()


class Formatter:
    """Centralized formatter for consistent output formatting"""
    
    @staticmethod
    def print_header(title: str, description: str = ""):
        """Print a formatted header section"""
        print("=" * 80)
        print(title)
        print("=" * 80)
        if description:
            print(description)
            print("-" * 80)
        print(f"Retrieved at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
    
    @staticmethod
    def print_section_header(title: str):
        """Print a section header"""
        print(f"\n{title}:")
        print("-" * 60)
    
    @staticmethod
    def print_success(message: str, indent: int = 0):
        """Print a success message"""
        indent_str = "  " * indent
        print(f"{indent_str}✓ {message}")
    
    @staticmethod
    def print_error(message: str, indent: int = 0):
        """Print an error message"""
        indent_str = "  " * indent
        print(f"{indent_str}✗ {message}")
    
    @staticmethod
    def print_warning(message: str, indent: int = 0):
        """Print a warning message"""
        indent_str = "  " * indent
        print(f"{indent_str}⚠️  {message}")
    
    @staticmethod
    def print_info(message: str, indent: int = 0):
        """Print an info message"""
        indent_str = "  " * indent
        print(f"{indent_str}ℹ️  {message}")
    
    @staticmethod
    def print_list_item(item: str, indent: int = 0):
        """Print a list item"""
        indent_str = "  " * indent
        print(f"{indent_str}- {item}")
    
    @staticmethod
    def print_key_value(key: str, value: Any, indent: int = 0):
        """Print a key-value pair"""
        indent_str = "  " * indent
        print(f"{indent_str}{key}: {value}")
    
    @staticmethod
    def print_separator():
        """Print a separator line"""
        print("=" * 80)
    
    @staticmethod
    def print_subsection(title: str):
        """Print a subsection header"""
        print(f"\n{title}:")
        print("-" * 40)
    
    @staticmethod
    def format_percentage(numerator: int, denominator: int) -> str:
        """Format a percentage"""
        if denominator == 0:
            return "0.0%"
        percentage = (numerator / denominator) * 100
        return f"{percentage:.1f}%"
    
    @staticmethod
    def format_status_icon(status: bool) -> str:
        """Format a status with an icon"""
        return "✓" if status else "✗"
    
    @staticmethod
    def print_table(headers: List[str], rows: List[List[Any]], indent: int = 0):
        """Print a formatted table"""
        if not rows:
            return
        
        indent_str = "  " * indent
        
        # Calculate column widths
        col_widths = []
        for i, header in enumerate(headers):
            max_width = len(header)
            for row in rows:
                if i < len(row):
                    max_width = max(max_width, len(str(row[i])))
            col_widths.append(max_width)
        
        # Print header
        header_line = indent_str + "|"
        separator_line = indent_str + "|"
        for i, header in enumerate(headers):
            header_line += f" {header:<{col_widths[i]}} |"
            separator_line += f" {'-' * col_widths[i]} |"
        
        print(header_line)
        print(separator_line)
        
        # Print rows
        for row in rows:
            row_line = indent_str + "|"
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    row_line += f" {str(cell):<{col_widths[i]}} |"
            print(row_line)
    
    @staticmethod
    def print_json_like(data: Dict[str, Any], indent: int = 0):
        """Print data in a JSON-like format"""
        indent_str = "  " * indent
        for key, value in data.items():
            if isinstance(value, dict):
                print(f"{indent_str}{key}:")
                Formatter.print_json_like(value, indent + 1)
            elif isinstance(value, list):
                print(f"{indent_str}{key}:")
                for item in value:
                    if isinstance(item, dict):
                        Formatter.print_json_like(item, indent + 1)
                    else:
                        print(f"{indent_str}  - {item}")
            else:
                print(f"{indent_str}{key}: {value}")
    
    @staticmethod
    def truncate_text(text: str, max_length: int = 100) -> str:
        """Truncate text to a maximum length"""
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + "..."


class Config:
    """Configuration management for the Security Policy Printer"""
    
    def __init__(self, subscription_id: str, resource_group: str, workspace_name: str,
                 graph_base_url: str, arm_base_url: str, max_items: int, output_file: str,
                 tenant_id: str | None = None, client_id: str | None = None, client_secret: str | None = None,
                 max_subitems: int = 10):
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.workspace_name = workspace_name
        self.graph_base_url = graph_base_url
        self.arm_base_url = arm_base_url
        self.max_items = max_items
        self.output_file = output_file
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.max_subitems = max_subitems
    
    @classmethod
    def from_file(cls, config_file: str = "config.json") -> "Config":
        """Load configuration from JSON file"""
        if not os.path.exists(config_file):
            raise FileNotFoundError(
                f"Configuration file '{config_file}' not found. "
                f"Please create a '{config_file}' file with the required configuration parameters."
            )
        
        with open(config_file, 'r') as f:
            data = json.load(f)
            if 'max_subitems' not in data:
                data['max_subitems'] = 10
            return cls(**data)
    
    def to_dict(self) -> dict:
        """Convert configuration to dictionary"""
        return {
            "subscription_id": self.subscription_id,
            "resource_group": self.resource_group,
            "workspace_name": self.workspace_name,
            "graph_base_url": self.graph_base_url,
            "arm_base_url": self.arm_base_url,
            "max_items": self.max_items,
            "output_file": self.output_file,
            "tenant_id": self.tenant_id,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "max_subitems": self.max_subitems
        }
    
    def save(self, config_file: str = "config.json"):
        """Save configuration to JSON file"""
        with open(config_file, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)


def get_access_tokens_from_file(token_file: str = "access_tokens.json") -> dict:
    """Read ARM and Graph tokens from a JSON file"""
    try:
        with open(token_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Token file '{token_file}' not found.")
        print("Please create a file named 'access_tokens.json' with your ARM and Graph tokens.")
        return {}


class APIClient:
    """Centralized API client for making requests to Microsoft Graph and ARM APIs"""
    
    def __init__(self, tokens: Dict[str, str], config: Config):
        self.config = config
        self.graph_token = tokens.get('graph', '')
        self.arm_token = tokens.get('arm', '')
        
        # Set up headers
        self.graph_headers = {
            "Authorization": f"Bearer {self.graph_token}",
            "Content-Type": "application/json"
        }
        self.arm_headers = {
            "Authorization": f"Bearer {self.arm_token}",
            "Content-Type": "application/json"
        }
    
    def graph_get(self, endpoint: str) -> requests.Response:
        """Make a GET request to Microsoft Graph API"""
        url = f"{self.config.graph_base_url}{endpoint}"
        return requests.get(url, headers=self.graph_headers)
    
    def graph_post(self, endpoint: str, data: Dict[str, Any]) -> requests.Response:
        """Make a POST request to Microsoft Graph API"""
        url = f"{self.config.graph_base_url}{endpoint}"
        return requests.post(url, headers=self.graph_headers, json=data)
    
    def arm_get(self, endpoint: str) -> requests.Response:
        """Make a GET request to Azure Resource Manager API"""
        url = f"{self.config.arm_base_url}{endpoint}"
        return requests.get(url, headers=self.arm_headers)
    
    def arm_post(self, endpoint: str, data: Dict[str, Any]) -> requests.Response:
        """Make a POST request to Azure Resource Manager API"""
        url = f"{self.config.arm_base_url}{endpoint}"
        return requests.post(url, headers=self.arm_headers, json=data)
    
    def log_analytics_query(self, query: str, timespan: str = "P7D") -> requests.Response:
        """Execute a Log Analytics query"""
        endpoint = f"/subscriptions/{self.config.subscription_id}/resourceGroups/{self.config.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.config.workspace_name}/api/query"
        
        url = f"{self.config.arm_base_url}{endpoint}?api-version=2020-08-01"
        
        payload = {
            "query": query,
            "timespan": timespan
        }
        
        return requests.post(url, headers=self.arm_headers, json=payload)
    
    def check_response(self, response: requests.Response, operation: str) -> bool:
        """Check if an API response was successful and handle common errors"""
        if response.status_code == 200:
            return True
        elif response.status_code == 204:
            print(f"✓ {operation}: No data found (204)")
            return True
        elif response.status_code == 401:
            print(f"✗ {operation}: Unauthorized (401) - Check token validity")
            return False
        elif response.status_code == 403:
            print(f"✗ {operation}: Forbidden (403) - Check permissions")
            return False
        elif response.status_code == 404:
            print(f"✗ {operation}: Not found (404)")
            return False
        else:
            print(f"✗ {operation}: HTTP {response.status_code}")
            print(f"  Response: {response.text}")
            return False


def setup_output(config: Config):
    """Setup output redirection to file"""
    out_file = open(config.output_file, "w", encoding="utf-8")
    sys.stdout = Tee(sys.stdout, out_file)
    sys.stderr = Tee(sys.stderr, out_file)
    return out_file 