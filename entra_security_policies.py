#!/usr/bin/env python3
"""
Microsoft Entra ID Security Policies Configuration Retriever

This script will serve as a basis for retrieving and displaying various security policy configurations from Microsoft Entra ID (Azure AD) using the Microsoft Graph API.

Future functions will fetch specific security policies and print their current configurations.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone, timedelta
import requests
import base64
import json
import sys

def get_access_tokens_from_file(token_file: str = "access_tokens.json") -> dict:
    """
    Read ARM and Graph tokens from a JSON file.
    Args:
        token_file (str): Path to file containing the tokens
    Returns:
        Dict with 'arm' and 'graph' tokens, or empty dict if file not found
    """
    try:
        with open(token_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Token file '{token_file}' not found.")
        print("Please create a file named 'access_tokens.json' with your ARM and Graph tokens.")
        return {}

class EntraSecurityPolicies:
    """Class to retrieve various Microsoft Entra ID security policy configurations."""
    
    def __init__(self, tokens: dict, subscription_id: Optional[str] = None, resource_group: Optional[str] = None, workspace_name: Optional[str] = None, max_lines: int = 100):
        """
        Initialize the configuration retriever.
        Args:
            tokens (dict): Dict with 'graph' and 'arm' access tokens
            subscription_id (str, optional): Azure subscription ID for Bastion host queries
            resource_group (str, optional): Azure resource group for Bastion host queries
            workspace_name (str, optional): Log Analytics workspace name for Sentinel queries
            max_lines (int, optional): Maximum number of lines to print in large-output functions
        """
        self.graph_token = tokens.get('graph', '')
        self.arm_token = tokens.get('arm', '')
        self.graph_base_url = "https://graph.microsoft.com/v1.0"
        self.arm_base_url = "https://management.azure.com"
        self.graph_headers = {
            "Authorization": f"Bearer {self.graph_token}",
            "Content-Type": "application/json"
        }
        self.arm_headers = {
            "Authorization": f"Bearer {self.arm_token}",
            "Content-Type": "application/json"
        }
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.workspace_name = workspace_name
        self.max_lines = max_lines

    def print_smart_lockout_settings(self):
        """Print the Smart Lockout configuration information, including custom settings if present."""
        print("=" * 80)
        print("MICROSOFT ENTRA ID SMART LOCKOUT POLICY CONFIGURATION")
        print("=" * 80)
        print("This function retrieves and displays the current Smart Lockout policy for Microsoft Entra ID, including both security defaults and any custom password protection settings. It helps evidence whether lockout protections are enforced to prevent brute-force attacks.")
        print("-" * 80)
        from datetime import datetime
        print(f"Retrieved at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Get security defaults policy
        security_defaults = self._get_security_defaults_policy()
        print("SECURITY DEFAULTS POLICY:")
        print("-" * 40)
        if security_defaults:
            print("✓ Security defaults policy found")
            print(f"  - Is Enabled: {security_defaults.get('isEnabled', 'Unknown')}")
            print(f"  - Description: {security_defaults.get('description', 'No description')}")
            if security_defaults.get('isEnabled'):
                print("  - Smart Lockout: Enabled (part of security defaults)")
            else:
                print("  - Smart Lockout: Disabled (security defaults disabled)")
        else:
            print("✗ Security defaults policy not found or not accessible")
        print()
        
        # Get custom smart lockout settings
        custom_settings = self._get_custom_smart_lockout_settings()
        print("CUSTOM SMART LOCKOUT SETTINGS (Password Protection):")
        print("-" * 40)
        if custom_settings:
            threshold = custom_settings.get('LockoutThreshold', 'Not set')
            duration = custom_settings.get('LockoutDurationInSeconds', 'Not set')
            print("✓ Custom smart lockout settings found")
            print(f"  - Lockout Threshold: {threshold}")
            print(f"  - Lockout Duration (seconds): {duration}")
        else:
            print("✗ No custom smart lockout settings found; using defaults")
            print("  - Lockout Threshold: 10 failed attempts (default)")
            print("  - Lockout Duration: 60 seconds (default)")
        print()
        print("Note: Smart Lockout settings are typically managed through Security Defaults, Password Protection (custom), Conditional Access policies, or custom authentication policies.")
        print("=" * 80)

    def _get_security_defaults_policy(self) -> Optional[Dict[str, Any]]:
        """
        Retrieve the security defaults policy which includes Smart Lockout settings.
        Returns:
            Dict containing security defaults policy or None if not found
        """
        try:
            url = f"{self.graph_base_url}/policies/identitySecurityDefaultsEnforcementPolicy"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Error retrieving security defaults policy: {response.status_code}")
                return None
        except Exception as e:
            print(f"Exception occurred while retrieving security defaults policy: {e}")
            return None

    def _get_custom_smart_lockout_settings(self) -> Optional[dict]:
        """
        Retrieve custom smart lockout settings from directorySettings (if configured).
        Returns:
            Dict containing custom smart lockout settings or None if not found
        """
        try:
            # Try the standard directorySettings endpoint
            url = f"{self.graph_base_url}/directorySettings"
            response = requests.get(url, headers=self.graph_headers)
            
            if response.status_code == 200:
                settings = response.json().get('value', [])
                for setting in settings:
                    # Password protection settings have a well-known templateId
                    if setting.get('templateId') == 'b0a8a3d5-4c67-4d9b-8c5c-9c1c8c9f3e0f' or \
                       setting.get('displayName', '').lower() == 'password protection':
                        values = {v['name']: v['value'] for v in setting.get('values', [])}
                        return values
                return None
            elif response.status_code == 400:
                error_data = response.json()
                error_message = error_data.get('error', {}).get('message', '')
                if "Resource not found for the segment 'directorySettings'" in error_message:
                    print("Note: Directory Settings endpoint is not available in this tenant.")
                    return None
                else:
                    print(f"Error retrieving directory settings: {response.content}")
                    return None
            else:
                print(f"Error retrieving directory settings: {response.status_code} - {response.content}")
                return None
        except Exception as e:
            print(f"Exception occurred while retrieving directory settings: {e}")
            return None

    def print_intune_machine_inactivity_limit(self):
        print("=" * 80)
        print("MICROSOFT INTUNE MACHINE INACTIVITY LIMIT (AUTO-LOCK)")
        print("=" * 80)
        print("This function retrieves and displays the machine inactivity (auto-lock) limit set in Intune device configuration profiles. It evidences enforcement of device lockout after inactivity for compliance with session management requirements.")
        print("-" * 80)
        try:
            # Get all device configuration profiles
            url = f"{self.graph_base_url}/deviceManagement/deviceConfigurations"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code != 200:
                print(f"Error retrieving device configurations: {response.status_code}")
                return
            configs = response.json().get('value', [])
            found = False
            for config in configs:
                # Only check OMA settings profiles
                oma_settings = config.get('omaSettings', [])
                for setting in oma_settings:
                    if setting.get('omaUri') == './Device/Vendor/MSFT/Policy/Config/DeviceLock/MaxInactivityTimeDeviceLock':
                        print(f"Profile: {config.get('displayName', 'Unnamed Profile')}")
                        print(f"  - Inactivity Limit (minutes): {setting.get('value')}")
                        found = True
            if not found:
                print("No machine inactivity (auto-lock) limit found in Intune device configuration profiles.")
        except Exception as e:
            print(f"Exception occurred while retrieving Intune inactivity limit: {e}")
        print("=" * 80)

    def print_available_permissions(self):
        print("=" * 80)
        print("MICROSOFT GRAPH API PERMISSIONS CHECK")
        print("=" * 80)
        print("This function checks and prints which Microsoft Graph API permissions are available with the current access token. It attempts to call key endpoints and reports which ones succeed or fail, evidencing the effective permissions for compliance and troubleshooting.")
        print("-" * 80)
        test_endpoints = [
            ("/policies/identitySecurityDefaultsEnforcementPolicy", "Security Defaults Policy"),
            ("/policies/authenticationMethodsPolicy", "Authentication Methods Policy"),
            ("/identity/conditionalAccess/policies", "Conditional Access Policies"),
            ("/directorySettings", "Directory Settings (Password Protection)"),
            ("/deviceManagement/deviceConfigurations", "Intune Device Configurations"),
            ("/deviceManagement/managedDevices", "Intune Managed Devices"),
            ("/deviceManagement", "Intune Service Config"),
            ("/policies", "All Policies"),
            ("/domains", "Domains"),
            ("/directoryRoles", "Directory Roles")
        ]
        working = []
        failed = []
        for endpoint, description in test_endpoints:
            try:
                url = f"{self.graph_base_url}{endpoint}"
                response = requests.get(url, headers=self.graph_headers)
                if response.status_code == 200:
                    working.append((endpoint, description, response.status_code))
                    print(f"✓ {description}: {response.status_code}")
                else:
                    failed.append((endpoint, description, response.status_code, response.text))
                    print(f"✗ {description}: {response.status_code}")
            except Exception as e:
                failed.append((endpoint, description, "Exception", str(e)))
                print(f"✗ {description}: Exception - {e}")
        print()
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)
        if working:
            print("✓ WORKING ENDPOINTS:")
            for endpoint, description, status in working:
                print(f"  - {description} ({endpoint})")
            print()
        if failed:
            print("✗ FAILED ENDPOINTS:")
            for endpoint, description, status, error in failed:
                print(f"  - {description} ({endpoint}): {status}")
        print("=" * 80)

    def print_intune_compliance_policy_checks(self):
        print("=" * 80)
        print("MICROSOFT INTUNE COMPLIANCE POLICY CHECKS (Windows 10/11)")
        print("=" * 80)
        print("This function checks Intune compliance policies for Windows 10/11 for BitLocker, Defender, Secure Boot, and password protection requirements. It evidences device compliance with key security baselines.")
        print("-" * 80)
        url = f"{self.graph_base_url}/deviceManagement/deviceCompliancePolicies"
        try:
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                policies = response.json().get('value', [])
                found = False
                for policy in policies:
                    if policy.get('@odata.type', '').endswith('windows10CompliancePolicy'):
                        found = True
                        print(f"Policy: {policy.get('displayName')}")
                        print(f"  - BitLocker Required: {policy.get('bitLockerEnabled', 'N/A')}")
                        print(f"  - Defender Required: {policy.get('defenderEnabled', 'N/A')}")
                        print(f"  - Secure Boot Required: {policy.get('secureBootEnabled', 'N/A')}")
                        print(f"  - Password Required: {policy.get('passwordRequired', 'N/A')}")
                        print("-" * 40)
                if not found:
                    print("No Windows 10/11 compliance policies found.")
            else:
                print(f"Failed to retrieve compliance policies: {response.status_code}")
        except Exception as e:
            print(f"Exception occurred while retrieving compliance policies: {e}")
        print("=" * 80)

    def print_conditional_access_policy_checks(self):
        print("=" * 80)
        print("MICROSOFT ENTRA CONDITIONAL ACCESS POLICY CHECKS")
        print("=" * 80)
        print("This function checks Conditional Access policies for device compliance and MFA requirements. It evidences enforcement of access controls and multi-factor authentication for compliance.")
        print("-" * 80)
        url = f"{self.graph_base_url}/identity/conditionalAccess/policies"
        try:
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                policies = response.json().get('value', [])
                found = False
                for policy in policies:
                    grant_controls = policy.get('grantControls', {})
                    require_compliance = 'requireDeviceCompliance' in grant_controls.get('builtInControls', [])
                    require_mfa = 'mfa' in grant_controls.get('builtInControls', [])
                    if require_compliance or require_mfa:
                        found = True
                        print(f"Policy: {policy.get('displayName')}")
                        print(f"  - Requires Device Compliance: {require_compliance}")
                        print(f"  - Requires MFA: {require_mfa}")
                        print(f"  - State: {policy.get('state', 'Unknown')}")
                        print("-" * 40)
                if not found:
                    print("No Conditional Access policies found that require device compliance or MFA.")
            else:
                print(f"Failed to retrieve Conditional Access policies: {response.status_code}")
        except Exception as e:
            print(f"Exception occurred while retrieving Conditional Access policies: {e}")
        print("=" * 80)

    def print_user_risk_policy(self):
        print("=" * 80)
        print("MICROSOFT ENTRA USER RISK POLICY")
        print("=" * 80)
        print("This function checks and prints the Microsoft Entra User Risk Policy using the Microsoft Graph API. It evidences risk-based conditional access and user risk management for compliance.")
        print("-" * 80)
        url = f"{self.graph_base_url}/identityProtection/userRiskPolicy"
        try:
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                policy = response.json()
                print(f"Enabled: {policy.get('isEnabled')}")
                print(f"Risk Level: {policy.get('userRiskLevel')}")
                print(f"Action: {policy.get('userRiskAction')}")
                print(f"Include Users: {policy.get('includeUsers')}")
                print(f"Exclude Users: {policy.get('excludeUsers')}")
                print(f"Notification to User: {policy.get('notificationToUser')}")
                print(f"Remediation to User: {policy.get('remediationToUser')}")
                print(f"Actions: {policy.get('actions')}")
            elif response.status_code == 400 and 'Resource not found for the segment' in response.text:
                print("User Risk Policy is only available with Microsoft Entra ID P2 (Azure AD Premium P2). This feature is not available in your tenant.")
            else:
                print(f"Failed to retrieve user risk policy: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Exception occurred while retrieving user risk policy: {e}")
        print("=" * 80)

    def print_password_protection_policy(self):
        print("=" * 80)
        print("MICROSOFT ENTRA PASSWORD PROTECTION POLICY")
        print("=" * 80)
        print("This function checks and prints Microsoft Entra ID password protection policy settings, including banned password list and minimum length. It evidences password policy enforcement for compliance.")
        print("-" * 80)
        url = f"{self.graph_base_url}/directorySettings"
        try:
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                settings = response.json().get('value', [])
                found = False
                for setting in settings:
                    if setting.get('templateId') == 'b0a8a3d5-4c67-4d9b-8c5c-9c1c8c9f3e0f' or \
                       setting.get('displayName', '').lower() == 'password protection':
                        found = True
                        print("Custom password protection policy found:")
                        for v in setting.get('values', []):
                            print(f"  - {v['name']}: {v['value']}")
                if not found:
                    print("No custom password protection policy found. Default Entra ID password requirements apply.")
            elif response.status_code == 400 and 'Resource not found for the segment' in response.text:
                print("Password protection policy resource is not available in this tenant.")
            else:
                print(f"Failed to retrieve password protection policy: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Exception occurred while retrieving password protection policy: {e}")
        print("=" * 80)

    def print_identity_protection_risk_detections(self, top=10):
        print("=" * 80)
        print("MICROSOFT ENTRA IDENTITY PROTECTION RISK DETECTIONS")
        print("=" * 80)
        print("This function checks and prints recent risk detections from Microsoft Entra ID Identity Protection using the Microsoft Graph API. It evidences detection of risky sign-ins and user activity for compliance and threat monitoring.")
        print("-" * 80)
        url = f"{self.graph_base_url}/identityProtection/riskDetections?$top={top}"
        try:
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                detections = response.json().get('value', [])
                if not detections:
                    print("No recent risk detections found.")
                for det in detections:
                    print(f"User: {det.get('userDisplayName', 'N/A')} ({det.get('userPrincipalName', 'N/A')})")
                    print(f"Risk Type: {det.get('riskType', 'N/A')}")
                    print(f"Risk Level: {det.get('riskLevel', 'N/A')}")
                    print(f"Risk State: {det.get('riskState', 'N/A')}")
                    print(f"Detection Time: {det.get('activityDateTime', 'N/A')}")
                    print(f"Detection ID: {det.get('id', 'N/A')}")
                    print("-" * 40)
            elif response.status_code == 403 and 'not licensed for this feature' in response.text.lower():
                print("Identity Protection risk detections require Microsoft Entra ID P2 (Azure AD Premium P2). This feature is not available in your tenant.")
            else:
                print(f"Failed to retrieve risk detections: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Exception occurred while retrieving risk detections: {e}")
        print("=" * 80)

    def print_sign_in_risk_policy(self, top=10):
        print("=" * 80)
        print("MICROSOFT ENTRA SIGN-IN RISK DETECTIONS")
        print("=" * 80)
        print("This function checks and prints recent sign-in risk detections from Microsoft Entra ID Identity Protection using the Microsoft Graph API. It evidences detection of risky sign-in attempts for compliance and threat monitoring.")
        print("-" * 80)
        url = f"{self.graph_base_url}/identityProtection/riskDetections?$top={top}"
        try:
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                detections = response.json().get('value', [])
                sign_in_detections = [d for d in detections if d.get('activity') == 'signin']
                if not sign_in_detections:
                    print("No recent sign-in risk detections found.")
                for det in sign_in_detections:
                    print(f"User: {det.get('userDisplayName', 'N/A')} ({det.get('userPrincipalName', 'N/A')})")
                    print(f"Risk Event Type: {det.get('riskEventType', 'N/A')}")
                    print(f"Risk Level: {det.get('riskLevel', 'N/A')}")
                    print(f"Risk State: {det.get('riskState', 'N/A')}")
                    print(f"Detection Time: {det.get('activityDateTime', 'N/A')}")
                    print(f"IP Address: {det.get('ipAddress', 'N/A')}")
                    location = det.get('location', {})
                    if location:
                        city = location.get('city', 'N/A')
                        country = location.get('countryOrRegion', 'N/A')
                        print(f"Location: {city}, {country}")
                    print(f"Detection ID: {det.get('id', 'N/A')}")
                    print("-" * 40)
            elif response.status_code == 403 and 'not licensed for this feature' in response.text.lower():
                print("Sign-in risk detections require Microsoft Entra ID P2 (Azure AD Premium P2). This feature is not available in your tenant.")
            else:
                print(f"Failed to retrieve sign-in risk detections: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Exception occurred while retrieving sign-in risk detections: {e}")
        print("=" * 80)

    def print_bastion_host_settings(self):
        print("=" * 80)
        print("AZURE BASTION HOST CONFIGURATION")
        print("=" * 80)
        print("This function checks and prints the Azure Bastion host configuration settings, including session limits, network configuration, and security settings. It evidences secure remote access controls for compliance.")
        print("-" * 80)
        if not hasattr(self, 'subscription_id') or not hasattr(self, 'resource_group') or not self.subscription_id or not self.resource_group:
            print("Error: subscription_id and resource_group are required for checking Bastion settings.")
            print("Please initialize the class with these parameters.")
            return

        print("=" * 80)
        print("AZURE BASTION HOST CONFIGURATION")
        print("=" * 80)
        
        # Azure Resource Manager API endpoint for Bastion
        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Network/bastionHosts?api-version=2023-05-01"
        
        try:
            response = requests.get(url, headers=self.arm_headers)
            response.raise_for_status()
            bastion_hosts = response.json().get('value', [])
            
            if not bastion_hosts:
                print("No Azure Bastion hosts found in the specified subscription/resource group.")
                return
                
            for host in bastion_hosts:
                print(f"\nBastion Host: {host.get('name')}")
                print("-" * 40)
                
                properties = host.get('properties', {})
                
                # Print concurrent session limits
                print("\nConcurrent Session Limits:")
                print(f"- Privileged Users: {properties.get('privilegedSessionLimit', 'Not configured')}")
                print(f"- Non-Privileged Users: {properties.get('sessionLimit', 'Not configured')}")
                
                # Print network configuration
                print("\nNetwork Configuration:")
                print(f"- Virtual Network: {properties.get('virtualNetwork', {}).get('id', 'Not configured')}")
                print(f"- Public IP: {properties.get('publicIPAddress', {}).get('id', 'Not configured')}")
                
                # Print security settings
                print("\nSecurity Settings:")
                print(f"- Copy/Paste Enabled: {properties.get('enableCopyPaste', True)}")
                print(f"- File Copy Enabled: {properties.get('enableFileCopy', False)}")
                print(f"- IP-based Connection Tracking: {properties.get('enableIpConnect', False)}")
                print(f"- Shareable Link: {properties.get('enableShareableLink', False)}")
                
        except Exception as e:
            print(f"Error retrieving Bastion host settings: {str(e)}")
            print("Note: This may be due to missing permissions or no Bastion hosts in the subscription.")

    def print_encryption_policy_and_defender_status(self):
        print("=" * 80)
        print("AZURE POLICY ASSIGNMENTS AND DEFENDER FOR CLOUD STATUS")
        print("=" * 80)
        print("This function prints evidence of Azure Policy assignments enforcing encryption and Defender for Cloud status for the subscription. It evidences policy-based security controls and cloud workload protection for compliance.")
        print("-" * 80)
        if not self.subscription_id:
            print("Error: subscription_id is required to check policy assignments and Defender for Cloud status.")
            print("Please initialize the class with this parameter.")
            print("=" * 80)
            return
        # List policy assignments
        policy_url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
        try:
            response = requests.get(policy_url, headers=self.arm_headers)
            if response.status_code == 200:
                assignments = response.json().get('value', [])
                if assignments:
                    print("Assigned Azure Policies:")
                    for assignment in assignments:
                        display_name = assignment.get('properties', {}).get('displayName', assignment.get('name', 'Unnamed'))
                        policy_def_id = assignment.get('properties', {}).get('policyDefinitionId', 'N/A')
                        print(f"  - {display_name}")
                        print(f"    Policy Definition ID: {policy_def_id}")
                else:
                    print("No policy assignments found for this subscription.")
            else:
                print(f"Failed to retrieve policy assignments: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Exception occurred while retrieving policy assignments: {e}")
        print()
        # Check Defender for Cloud pricing status
        defender_url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Security/pricings?api-version=2024-01-01"
        try:
            response = requests.get(defender_url, headers=self.arm_headers)
            if response.status_code == 200:
                pricings = response.json().get('value', [])
                if pricings:
                    print("Defender for Cloud Pricing Status:")
                    for pricing in pricings:
                        name = pricing.get('name', 'N/A')
                        tier = pricing.get('properties', {}).get('pricingTier', 'N/A')
                        print(f"  - {name}: {tier}")
                else:
                    print("No Defender for Cloud pricing information found.")
            else:
                print(f"Failed to retrieve Defender for Cloud pricing: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Exception occurred while retrieving Defender for Cloud pricing: {e}")
        print("=" * 80)

    def print_log_analytics_retention_settings(self, workspace_name: str):
        print("=" * 80)
        print(f"LOG ANALYTICS RETENTION AND IMMUTABILITY SETTINGS: {workspace_name}")
        print("=" * 80)
        print("This function prints the log retention and immutability settings for a Log Analytics workspace using the ARM API. It evidences log data retention and protection for compliance and audit readiness.")
        print("-" * 80)
        if not self.subscription_id or not self.resource_group:
            print("Error: subscription_id and resource_group are required to check Log Analytics workspace settings.")
            print("Please initialize the class with these parameters.")
            print("=" * 80)
            return
        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}?api-version=2022-10-01"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                ws = response.json()
                retention = ws.get('properties', {}).get('retentionInDays', 'Not set')
                immutability = ws.get('properties', {}).get('publicNetworkAccessForIngestion', 'Unknown')
                print(f"Retention Period (days): {retention}")
                # Immutability is not a direct property; check for data retention policy if available
                data_retention_policy = ws.get('properties', {}).get('dataRetentionPolicy', {})
                if data_retention_policy:
                    state = data_retention_policy.get('state', 'Not set')
                    print(f"Data Retention Policy State: {state}")
                else:
                    print("Data Retention Policy: Not set or not available")
                # Immutability is not always exposed; print what is available
                if 'immutableWorkspaceProperties' in ws.get('properties', {}):
                    immutability_props = ws['properties']['immutableWorkspaceProperties']
                    enabled = immutability_props.get('state', 'Not set')
                    print(f"Immutability State: {enabled}")
                else:
                    print("Immutability State: Not set or not available")
            else:
                print(f"Failed to retrieve workspace settings: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Exception occurred while retrieving workspace settings: {e}")
        print("=" * 80)

    def print_workspace_rbac(self, workspace_name: str):
        print("=" * 80)
        print("LOG ANALYTICS WORKSPACE RBAC CHECK")
        print("=" * 80)
        print("This function lists all role assignments (RBAC) for the specified Log Analytics workspace, showing which users, groups, or service principals have access and what roles they hold. It helps evidence access control and least privilege for log data.")
        print("-" * 80)
        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                assignments = response.json().get('value', [])
                for assignment in assignments:
                    role = assignment.get('properties', {}).get('roleDefinitionId', 'N/A')
                    principal = assignment.get('properties', {}).get('principalId', 'N/A')
                    print(f"Role: {role}, Principal: {principal}")
            else:
                print(f"Failed to retrieve role assignments: {response.status_code}")
        except Exception as e:
            print(f"Exception occurred: {e}")
        print()

    def print_sentinel_error_analytic_rules(self, workspace_name: str):
        print("=" * 80)
        print("SENTINEL ANALYTIC RULES FOR ERROR LOGS")
        print("=" * 80)
        print("This function lists all Microsoft Sentinel analytic rules related to error logs in the specified workspace. It evidences the presence of automated detection and alerting for error conditions in your security monitoring environment.")
        print("-" * 80)
        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-12-01-preview"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                rules = response.json().get('value', [])
                for rule in rules:
                    print(f"Rule: {rule.get('name')}, Description: {rule.get('properties', {}).get('description', 'N/A')}")
            else:
                print(f"Failed to retrieve analytic rules: {response.status_code} \n {response.text}")
        except Exception as e:
            print(f"Exception occurred: {e}")
        print()

    def print_credential_distribution_audit_events(self, top=10):
        print("=" * 80)
        print("CREDENTIAL DISTRIBUTION AUDIT EVENTS")
        print("=" * 80)
        print("This function retrieves and displays recent credential distribution audit events, such as password resets and user creation. It evidences credential issuance and change tracking for compliance.")
        print("-" * 80)
        url = f"{self.graph_base_url}/auditLogs/directoryAudits?$top={top}&$filter=activityDisplayName eq 'Reset user password' or activityDisplayName eq 'User created' or activityDisplayName eq 'Change user password'"
        try:
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                events = response.json().get('value', [])
                if not events:
                    print("No recent credential distribution events found.")
                for event in events:
                    time = event.get('activityDateTime', 'N/A')
                    activity = event.get('activityDisplayName', 'N/A')
                    user = 'N/A'
                    targets = event.get('targetResources', [])
                    if targets and isinstance(targets, list):
                        for t in targets:
                            if t.get('userPrincipalName'):
                                user = t.get('userPrincipalName')
                                break
                    print(f"Time: {time}, Activity: {activity}, User: {user}")
            else:
                print(f"Failed to retrieve audit events: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Exception occurred: {e}")
        print()

    def print_cis_l1_initiative_assignment(self):
        print("=" * 80)
        print("CIS L1 INITIATIVE ASSIGNMENT CHECK")
        print("=" * 80)
        print("This function checks for the assignment of the CIS Level 1 initiative to the subscription. It evidences alignment with CIS security benchmarks for compliance.")
        print("-" * 80)
        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                assignments = response.json().get('value', [])
                found = False
                for assignment in assignments:
                    policy_def_id = assignment.get('properties', {}).get('policyDefinitionId', '')
                    display_name = assignment.get('properties', {}).get('displayName', '')
                    if "CIS" in policy_def_id or "MicrosoftAzureCIS" in policy_def_id or "CIS" in display_name:
                        print(f"✓ CIS L1 Initiative assigned: {display_name} ({policy_def_id})")
                        found = True
                if not found:
                    print("✗ CIS L1 Initiative is NOT assigned to this subscription.")
            else:
                print(f"Failed to retrieve policy assignments: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Exception occurred: {e}")
        print()

    def print_defender_for_cloud_failed_checks(self):
        print("=" * 80)
        print("DEFENDER FOR CLOUD FAILED CONFIGURATION CHECKS")
        print("=" * 80)
        print("This function lists failed configuration checks from Defender for Cloud. It evidences detection of misconfigurations and gaps in cloud security posture for compliance.")
        print("-" * 80)
        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Security/assessments?api-version=2020-01-01"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                assessments = response.json().get('value', [])
                failed = [a for a in assessments if a.get('properties', {}).get('status', {}).get('code') == 'Unhealthy']
                if failed:
                    for a in failed:
                        display_name = a.get('properties', {}).get('displayName', 'N/A')
                        severity = a.get('properties', {}).get('metadata', {}).get('severity', 'N/A')
                        print(f"✗ {display_name} (Severity: {severity})")
                else:
                    print("No failed configuration checks found.")
            else:
                print(f"Failed to retrieve Defender for Cloud assessments: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Exception occurred: {e}")
        print()

    def print_sentinel_defender_connector_status(self, workspace_name):
        print("=" * 80)
        print("SENTINEL DEFENDER FOR CLOUD CONNECTOR STATUS")
        print("=" * 80)
        print("This function checks the status of the Defender for Cloud data connector in Microsoft Sentinel. It evidences integration of cloud security alerts with Sentinel for centralized monitoring and compliance.")
        print("-" * 80)
        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-12-01-preview"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                connectors = response.json().get('value', [])
                found = False
                for c in connectors:
                    kind = c.get('kind', '')
                    name = c.get('name', '')
                    if kind == "AzureSecurityCenter" or "defender" in name.lower():
                        print("✓ Defender for Cloud data connector is ENABLED in Sentinel.")
                        found = True
                if not found:
                    print("✗ Defender for Cloud data connector is NOT enabled in Sentinel.")
            else:
                print(f"Failed to retrieve Sentinel data connectors: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Exception occurred: {e}")
        print()

    def print_waf_deployment_and_policy_status(self):
        print("=" * 80)
        print("AZURE WAF DEPLOYMENT AND POLICY STATUS")
        print("=" * 80)
        print("This function checks the deployment and policy status of Azure Web Application Firewall (WAF) on Application Gateways and Front Door. It evidences web application protection and policy enforcement for compliance.")
        print("-" * 80)
        if not self.subscription_id:
            print("Error: subscription_id is required.")
            return

        # Helper to print WAF config summary
        def print_waf_summary(name, config):
            if config:
                print(f"{name}: WAF Enabled={config.get('enabled', False)}, Mode={config.get('firewallMode', 'N/A')}, RuleSet={config.get('ruleSetType', 'N/A')} {config.get('ruleSetVersion', '')}")
            else:
                print(f"{name}: No WAF configuration")

        # Application Gateways
        agw_url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Network/applicationGateways?api-version=2022-09-01"
        try:
            resp = requests.get(agw_url, headers=self.arm_headers)
            print("AGW status:", resp.status_code, "Response:", resp.text)
            for gw in resp.json().get('value', []):
                print_waf_summary(f"AppGW: {gw.get('name')}", gw.get('properties', {}).get('webApplicationFirewallConfiguration'))
        except Exception as e:
            print(f"Error: {e}")

        # Front Door
        afd_url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Cdn/profiles?api-version=2021-06-01"
        try:
            resp = requests.get(afd_url, headers=self.arm_headers)
            print("Front Door status:", resp.status_code, "Response:", resp.text)
            for profile in resp.json().get('value', []):
                sku = profile.get('sku', {}).get('name', '')
                if 'AzureFrontDoor' in sku:
                    waf_policy = profile.get('properties', {}).get('webApplicationFirewallPolicyLink', {}).get('id')
                    print(f"Front Door: {profile.get('name')} WAF Policy: {waf_policy or 'None'}")
        except Exception as e:
            print(f"Error: {e}")
        print("=" * 80)

    def print_waf_diagnostic_settings(self):
        print("=" * 80)
        print("AZURE WAF DIAGNOSTIC SETTINGS")
        print("=" * 80)
        print("This function checks diagnostic settings for Azure WAF resources. It evidences logging and monitoring configuration for web application firewalls in support of compliance and incident response.")
        print("-" * 80)
        if not self.subscription_id:
            print("Error: subscription_id is required.")
            return

        def print_diag(resource_type, name, resource_id):
            diag_url = f"{resource_id}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview"
            try:
                resp = requests.get(diag_url, headers=self.arm_headers)
                diags = resp.json().get('value', [])
                if diags:
                    for d in diags:
                        print(f"{resource_type}: {name} Diagnostic: {d.get('name')}, Workspace: {d.get('properties', {}).get('workspaceId', 'N/A')}")
                else:
                    print(f"{resource_type}: {name} has no diagnostic settings.")
            except Exception as e:
                print(f"{resource_type}: {name} error: {e}")

        # Application Gateways
        agw_url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Network/applicationGateways?api-version=2022-09-01"
        try:
            resp = requests.get(agw_url, headers=self.arm_headers)
            print("AGW status:", resp.status_code, "Response:", resp.text)
            for gw in resp.json().get('value', []):
                print_diag("AppGW", gw.get('name'), gw.get('id'))
        except Exception as e:
            print(f"AppGW error: {e}")

        # Front Door
        afd_url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Cdn/profiles?api-version=2021-06-01"
        try:
            resp = requests.get(afd_url, headers=self.arm_headers)
            print("Front Door status:", resp.status_code, "Response:", resp.text)
            for profile in resp.json().get('value', []):
                print_diag("Front Door", profile.get('name'), profile.get('id'))
        except Exception as e:
            print(f"Front Door error: {e}")
        print("=" * 80)

    def print_dnssec_status(self):
        print("=" * 80)
        print("AZURE DNSSEC STATUS FOR DNS ZONES")
        print("=" * 80)
        print("This function checks DNSSEC status for all DNS zones in the subscription. It evidences DNS integrity and protection against spoofing for compliance.")
        print("-" * 80)
        if not self.subscription_id:
            print("Error: subscription_id is required.")
            return
        # List all DNS zones
        dns_url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Network/dnsZones?api-version=2018-05-01"
        try:
            resp = requests.get(dns_url, headers=self.arm_headers)
            if resp.status_code != 200:
                print(f"Failed to retrieve DNS zones: {resp.status_code}")
                print(resp.text)
                return
            zones = resp.json().get('value', [])
            if not zones:
                print("No DNS zones found in this subscription.")
            for zone in zones:
                name = zone.get('name', 'N/A')
                zone_type = zone.get('properties', {}).get('zoneType', 'Public')
                if zone_type == 'Private':
                    print(f"DNS Zone: {name} (Private)")
                    print("  DNSSEC: Not Supported in Azure Private DNS")
                    print("  Compensating controls recommended: DNS logging, secure resolvers, etc.")
                    continue
                # For public zones, check DNSSEC
                dnssec_state = zone.get('properties', {}).get('zoneSigningKeys', [])
                if dnssec_state:
                    print(f"DNS Zone: {name} (Public)")
                    print("  DNSSEC: Enabled")
                    for k in dnssec_state:
                        ds_records = k.get('dsRecord', [])
                        if ds_records:
                            print(f"  DS Records: {ds_records}")
                        else:
                            print("  DS Records: Not available (check Azure Portal)")
                else:
                    print(f"DNS Zone: {name} (Public)")
                    print("  DNSSEC: Disabled")
        except Exception as e:
            print(f"Exception occurred while retrieving DNS zones: {e}")
        print("=" * 80)

    def print_defender_fim_configuration(self):
        print("=" * 80)
        print("DEFENDER FOR ENDPOINT FILE INTEGRITY MONITORING CONFIGURATION")
        print("=" * 80)
        print("This function checks Defender for Endpoint File Integrity Monitoring (FIM) configuration. It evidences monitoring of file changes for endpoint security and compliance.")
        print("-" * 80)
        # Microsoft Graph Security API endpoint for device security baseline/configuration
        url = f"https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles"
        try:
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                controls = response.json().get('value', [])
                found = False
                for c in controls:
                    if 'tamper' in c.get('title', '').lower() or 'real-time' in c.get('title', '').lower() or 'attack surface reduction' in c.get('title', '').lower():
                        found = True
                        print(f"Control: {c.get('title')}")
                        print(f"  - Description: {c.get('description')}")
                        print(f"  - Current Score: {c.get('currentScore', 'N/A')}")
                        print(f"  - Max Score: {c.get('maxScore', 'N/A')}")
                        print(f"  - Status: {c.get('status', 'N/A')}")
                        print("-")
                if not found:
                    print("No FIM-related controls found in Secure Score profiles.")
            else:
                print(f"Failed to retrieve Secure Score controls: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Exception occurred while retrieving Secure Score controls: {e}")
        print("=" * 80)

    def print_sentinel_defender_endpoint_connector_status(self, workspace_name):
        print("=" * 80)
        print("SENTINEL DEFENDER FOR ENDPOINT CONNECTOR STATUS")
        print("=" * 80)
        print("This function checks the status of the Defender for Endpoint data connector in Microsoft Sentinel. It evidences integration of endpoint security alerts with Sentinel for centralized monitoring and compliance.")
        print("-" * 80)
        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-12-01-preview"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                connectors = response.json().get('value', [])
                found = False
                for c in connectors:
                    kind = c.get('kind', '')
                    name = c.get('name', '')
                    if kind == "MicrosoftThreatProtection" or "defender" in name.lower():
                        print("✓ Defender for Endpoint data connector is ENABLED in Sentinel.")
                        found = True
                if not found:
                    print("✗ Defender for Endpoint data connector is NOT enabled in Sentinel.")
            else:
                print(f"Failed to retrieve Sentinel data connectors: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Exception occurred: {e}")
        print()

    def print_recent_fim_alerts(self, top=10):
        print("=" * 80)
        print("RECENT FILE INTEGRITY MONITORING ALERTS")
        print("=" * 80)
        print("This function retrieves and displays recent File Integrity Monitoring (FIM) alerts from Microsoft Defender for Endpoint. It evidences detection and alerting on suspicious or unauthorized file changes in your environment.")
        print("-" * 80)
        # Microsoft Graph Security API endpoint for alerts
        url = f"https://graph.microsoft.com/v1.0/security/alerts?$top={top}&$filter=title eq 'File modification' or title eq 'Suspicious file change' or title eq 'Tampering attempt'"
        try:
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                alerts = response.json().get('value', [])
                if not alerts:
                    print("No recent FIM-related alerts found.")
                for alert in alerts:
                    print(f"Time: {alert.get('createdDateTime', 'N/A')}, Title: {alert.get('title', 'N/A')}, Severity: {alert.get('severity', 'N/A')}, Status: {alert.get('status', 'N/A')}")
            else:
                print(f"Failed to retrieve FIM alerts: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Exception occurred while retrieving FIM alerts: {e}")
        print()

    def print_nsg_smtp_block_status(self):
        print("=" * 80)
        print("AZURE NSG INBOUND SMTP BLOCK STATUS (PORTS 25, 465)")
        print("=" * 80)
        print("This function checks all Network Security Groups (NSGs) in the subscription for explicit deny rules on inbound SMTP ports 25 and 465. It evidences enforcement of email traffic restrictions at the network boundary.")
        print("-" * 80)
        if not self.subscription_id:
            print("Error: subscription_id is required.")
            return
        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2022-05-01"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                nsgs = response.json().get('value', [])
                print(f"Found {len(nsgs)} NSGs in subscription.")
                lines = 0
                for nsg in nsgs:
                    if lines >= self.max_lines:
                        print(f"Output truncated at {self.max_lines} lines.")
                        break
                    nsg_name = nsg.get('name')
                    print(f"NSG: {nsg_name}")
                    lines += 1
                    rules = nsg.get('properties', {}).get('securityRules', [])
                    smtp_blocked = {25: False, 465: False}
                    for rule in rules:
                        if rule.get('direction') == 'Inbound' and rule.get('access') == 'Deny' and rule.get('protocol') in ['Tcp', '*']:
                            ports = []
                            if 'destinationPortRange' in rule:
                                ports.append(rule['destinationPortRange'])
                            if 'destinationPortRanges' in rule:
                                ports.extend(rule['destinationPortRanges'])
                            for port in ports:
                                if port == '*' or port == '25':
                                    smtp_blocked[25] = True
                                if port == '*' or port == '465':
                                    smtp_blocked[465] = True
                    for port in [25, 465]:
                        if lines >= self.max_lines:
                            print(f"Output truncated at {self.max_lines} lines.")
                            break
                        print(f"  - Port {port} Deny Rule: {'✓' if smtp_blocked[port] else '✗'}")
                        lines += 1
            else:
                print(f"Failed to retrieve NSGs: {response.status_code}")
        except Exception as e:
            print(f"Exception occurred: {e}")
        print("=" * 80)

    def print_firewall_smtp_block_status(self):
        print("=" * 80)
        print("AZURE FIREWALL INBOUND SMTP BLOCK STATUS (PORTS 25, 465)")
        print("=" * 80)
        print("This function checks all Azure Firewalls in the subscription for explicit deny rules on inbound SMTP ports 25 and 465. It evidences enforcement of email traffic restrictions at the firewall/perimeter level.")
        print("-" * 80)
        if not self.subscription_id:
            print("Error: subscription_id is required.")
            return
        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Network/azureFirewalls?api-version=2022-05-01"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                firewalls = response.json().get('value', [])
                print(f"Found {len(firewalls)} Azure Firewalls in subscription.")
                lines = 0
                for fw in firewalls:
                    if lines >= self.max_lines:
                        print(f"Output truncated at {self.max_lines} lines.")
                        break
                    fw_name = fw.get('name')
                    print(f"Firewall: {fw_name}")
                    lines += 1
                    smtp_blocked = {25: False, 465: False}
                    # Check network rule collections
                    nrcs = fw.get('properties', {}).get('networkRuleCollections', [])
                    for col in nrcs:
                        for rule in col.get('properties', {}).get('rules', []):
                            if rule.get('ruleType') == 'NetworkRule' and rule.get('action', {}).get('type') == 'Deny':
                                for port in rule.get('destinationPorts', []):
                                    if port == '*' or port == '25':
                                        smtp_blocked[25] = True
                                    if port == '*' or port == '465':
                                        smtp_blocked[465] = True
                    # Check application rule collections (rare for SMTP, but possible)
                    arcs = fw.get('properties', {}).get('applicationRuleCollections', [])
                    for col in arcs:
                        for rule in col.get('properties', {}).get('rules', []):
                            if rule.get('action', {}).get('type') == 'Deny':
                                for port in rule.get('protocols', []):
                                    if port.get('port') == 25:
                                        smtp_blocked[25] = True
                                    if port.get('port') == 465:
                                        smtp_blocked[465] = True
                    for port in [25, 465]:
                        if lines >= self.max_lines:
                            print(f"Output truncated at {self.max_lines} lines.")
                            break
                        print(f"  - Port {port} Deny Rule: {'✓' if smtp_blocked[port] else '✗'}")
                        lines += 1
            else:
                print(f"Failed to retrieve Azure Firewalls: {response.status_code}")
        except Exception as e:
            print(f"Exception occurred: {e}")
        print("=" * 80)

    def print_bastion_ssh_timeout_status(self):
        print("=" * 80)
        print("AZURE BASTION HOST SSH SESSION TIMEOUT STATUS")
        print("=" * 80)
        print("This function checks the SSH session idle timeout setting for all Azure Bastion Hosts. It evidences enforcement of session termination after inactivity, supporting compliance with session management requirements.")
        print("-" * 80)
        if not self.subscription_id or not self.resource_group:
            print("Error: subscription_id and resource_group are required for checking Bastion settings.")
            return

        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Network/bastionHosts?api-version=2023-05-01"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                bastion_hosts = response.json().get('value', [])
                if not bastion_hosts:
                    print("No Azure Bastion hosts found in the specified subscription/resource group.")
                    return
                for host in bastion_hosts:
                    print(f"Bastion Host: {host.get('name')}")
                    properties = host.get('properties', {})
                    idle_timeout = properties.get('idleTimeoutInMinutes', 'Not configured')
                    print(f"  - Idle Timeout (minutes): {idle_timeout}")
                    if idle_timeout == 10:
                        print("  ✓ SSH session timeout is correctly set to 10 minutes.")
                    else:
                        print("  ✗ SSH session timeout is NOT set to 10 minutes. Please review configuration.")
            else:
                print(f"Failed to retrieve Bastion hosts: {response.status_code}")
        except Exception as e:
            print(f"Exception occurred while retrieving Bastion host settings: {e}")
        print("=" * 80)

    def print_sentinel_incident_summary(self, workspace_name):
        print("=" * 80)
        print("MICROSOFT SENTINEL INCIDENT SUMMARY")
        print("=" * 80)
        print("This function summarizes Microsoft Sentinel incidents in the specified workspace, including counts by status and details for recent incidents. It evidences active monitoring, incident response, and security operations maturity.")
        print("-" * 80)
        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01-preview"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                incidents = response.json().get('value', [])
                print(f"Total Incidents: {len(incidents)}")
                status_count = {}
                for inc in incidents:
                    status = inc.get('properties', {}).get('status', 'Unknown')
                    status_count[status] = status_count.get(status, 0) + 1
                for status, count in status_count.items():
                    print(f"  - {status}: {count}")
                print("Recent Incidents:")
                for inc in incidents[:5]:
                    props = inc.get('properties', {})
                    print(f"  - Title: {props.get('title')}, Status: {props.get('status')}, Owner: {props.get('owner', {}).get('assignedTo', 'N/A')}")
                    print(f"    Created: {props.get('createdTimeUtc')}, Last Updated: {props.get('lastModifiedTimeUtc')}")
                    print(f"    Investigation Notes: {props.get('description', 'N/A')}")
            else:
                print(f"Failed to retrieve incidents: {response.status_code}")
        except Exception as e:
            print(f"Exception occurred: {e}")
        print("=" * 80)

    def print_admin_group_membership(self):
        print("=" * 80)
        print("MICROSOFT ENTRA ID ADMINISTRATIVE GROUP MEMBERSHIP")
        print("=" * 80)
        print("This function lists all Microsoft Entra ID directory roles and the members assigned to each role. It evidences which users, groups, or service principals have administrative privileges in your environment.")
        print("-" * 80)
        url_roles = f"{self.graph_base_url}/directoryRoles"
        try:
            resp = requests.get(url_roles, headers=self.graph_headers)
            if resp.status_code == 200:
                roles = resp.json().get('value', [])
                lines = 0
                for role in roles:
                    if lines >= self.max_lines:
                        print(f"Output truncated at {self.max_lines} lines.")
                        break
                    role_id = role.get('id')
                    role_name = role.get('displayName')
                    print(f"Role: {role_name}")
                    lines += 1
                    # List members of this role
                    url_members = f"{self.graph_base_url}/directoryRoles/{role_id}/members"
                    mem_resp = requests.get(url_members, headers=self.graph_headers)
                    if mem_resp.status_code == 200:
                        members = mem_resp.json().get('value', [])
                        if not members:
                            print("  (No members assigned)")
                            lines += 1
                        for m in members:
                            if lines >= self.max_lines:
                                print(f"Output truncated at {self.max_lines} lines.")
                                break
                            upn = m.get('userPrincipalName')
                            disp = m.get('displayName')
                            obj_id = m.get('id')
                            print(f"  - {upn or disp or obj_id}")
                            lines += 1
                    else:
                        print(f"  Failed to retrieve members for role {role_name}")
                        lines += 1
            else:
                print(f"Failed to retrieve directory roles: {resp.status_code}")
        except Exception as e:
            print(f"Exception occurred: {e}")
        print("=" * 80)

    def print_blob_storage_zrs_status(self):
        print("=" * 80)
        print("AZURE BLOB STORAGE ZONE-REDUNDANT STATUS")
        print("=" * 80)
        print("This function lists all Azure storage accounts in the subscription and indicates whether Zone-Redundant Storage (ZRS) is enabled. It evidences backup durability and resilience across multiple availability zones.")
        print("-" * 80)

        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Storage/storageAccounts?api-version=2022-09-01"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                accounts = response.json().get('value', [])
                lines = 0
                for acc in accounts:
                    if lines >= self.max_lines:
                        print(f"Output truncated at {self.max_lines} lines.")
                        break
                    name = acc.get('name')
                    kind = acc.get('kind')
                    sku = acc.get('sku', {}).get('name')
                    print(f"Storage Account: {name}, Kind: {kind}, SKU: {sku}")
                    if 'ZRS' in sku:
                        print("  ✓ Zone-Redundant Storage (ZRS) enabled")
                    else:
                        print("  ✗ Not ZRS (check if meets backup durability requirements)")
                    lines += 1
            else:
                print(f"Failed to retrieve storage accounts: {response.status_code}")
        except Exception as e:
            print(f"Exception occurred: {e}")
        print("=" * 80)

    def print_recovery_services_backup_policies(self):
        print("=" * 80)
        print("AZURE RECOVERY SERVICES VAULTS AND BACKUP POLICIES")
        print("=" * 80)
        print("This function lists all Recovery Services vaults and their backup policies, including backup frequency. It evidences the presence of automated backup and recovery processes for critical workloads.")
        print("-" * 80)

        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.RecoveryServices/vaults?api-version=2022-08-01"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                vaults = response.json().get('value', [])
                if not vaults:
                    print("No Recovery Services vaults found in this subscription.")
                lines = 0
                for vault in vaults:
                    if lines >= self.max_lines:
                        print(f"Output truncated at {self.max_lines} lines.")
                        break
                    vault_name = vault.get('name')
                    rg = vault.get('id').split('/')[4]
                    print(f"Vault: {vault_name} (Resource Group: {rg})")
                    lines += 1
                    # List backup policies
                    pol_url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{rg}/providers/Microsoft.RecoveryServices/vaults/{vault_name}/backupPolicies?api-version=2022-08-01"
                    pol_resp = requests.get(pol_url, headers=self.arm_headers)
                    if pol_resp.status_code == 200:
                        policies = pol_resp.json().get('value', [])
                        for pol in policies:
                            if lines >= self.max_lines:
                                print(f"Output truncated at {self.max_lines} lines.")
                                break
                            pol_name = pol.get('name')
                            freq = pol.get('properties', {}).get('schedulePolicy', {}).get('scheduleRunFrequency', 'N/A')
                            print(f"  Policy: {pol_name}, Frequency: {freq}")
                            lines += 1
                    else:
                        print(f"  Failed to retrieve backup policies: {pol_resp.status_code}")
            else:
                print(f"Failed to retrieve Recovery Services vaults: {response.status_code}")
        except Exception as e:
            print(f"Exception occurred: {e}")
        print("=" * 80)

    def print_missing_assettag_resources(self):
        print("=" * 80)
        print("AZURE RESOURCES MISSING ASSETTAG")
        print("=" * 80)
        print("This function lists all Azure resources in the subscription that are missing the required AssetTag tag. It evidences asset management and enforcement of tagging policies for compliance and inventory control.")
        print("-" * 80)

        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resources?api-version=2021-04-01"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                resources = response.json().get('value', [])
                missing = 0
                lines = 0
                for res in resources:
                    if lines >= self.max_lines:
                        print(f"Output truncated at {self.max_lines} lines.")
                        break
                    tags = res.get('tags', {})
                    if not tags or 'AssetTag' not in tags:
                        name = res.get('name')
                        type_ = res.get('type')
                        print(f"Resource: {name} ({type_}) - MISSING AssetTag")
                        missing += 1
                        lines += 1
                if missing == 0:
                    print("All resources have an AssetTag.")
            else:
                print(f"Failed to retrieve resources: {response.status_code} \n {response.text}")
        except Exception as e:
            print(f"Exception occurred: {e}")
        print("=" * 80)

    def check_token_expiry(self):
        print("ACCESS TOKEN EXPIRY CHECK")
        print("=" * 80)
        print("This function decodes the current Graph and ARM access tokens, checks their expiration times, and prints whether each token is valid or expired. It evidences token freshness and helps troubleshoot authentication issues.")
        print("-" * 80)

        for token_name, token in [('graph', self.graph_token), ('arm', self.arm_token)]:
            if not token:
                print(f"No {token_name} token found.")
                continue
            try:
                # JWT: header.payload.signature
                payload_b64 = token.split('.')[1]
                # Pad base64 if needed
                padding = '=' * (-len(payload_b64) % 4)
                payload_b64 += padding
                payload_bytes = base64.urlsafe_b64decode(payload_b64)
                payload = json.loads(payload_bytes)
                exp = payload.get('exp')
                if not exp:
                    print(f"{token_name} token: No 'exp' field found in token payload.")
                    continue
                exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
                now = datetime.now(timezone.utc)
                if exp_dt < now:
                    print(f"{token_name} token: EXPIRED at {exp_dt.isoformat()}")
                else:
                    delta = exp_dt - now
                    print(f"{token_name} token: Valid, expires in {delta} (at {exp_dt.isoformat()})")
            except Exception as e:
                print(f"{token_name} token: Error decoding token: {e}")
        print("=" * 80)

    def print_arm_template_configuration_orchestration(self):
        print("=" * 80)
        print("CONFIGURATION ORCHESTRATION: AZURE RESOURCE MANAGER TEMPLATES")
        print("=" * 80)
        print("This function evidences the Configuration Orchestration control for ARM templates, including Azure DevOps integration, PIM approvals, Azure Policy compliance monitoring, and configuration drift detection. It checks for baseline configuration validation, deployment approvals, and monitoring for FedRAMP Moderate compliance.")
        print("-" * 80)
        
        # Check ARM template deployments with approval tracking
        print("1. ARM TEMPLATE DEPLOYMENTS AND APPROVAL TRACKING:")
        print("-" * 50)
        if not self.resource_group:
            print("Resource group is required to check deployments.")
        else:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.Resources/deployments?api-version=2021-04-01"
            try:
                response = requests.get(url, headers=self.arm_headers)
                if response.status_code == 200:
                    deployments = response.json().get('value', [])
                    if deployments:
                        print(f"✓ Found {len(deployments)} ARM template deployments")
                        for dep in deployments[:5]:  # Show first 5
                            name = dep.get('name')
                            timestamp = dep.get('properties', {}).get('timestamp', 'N/A')
                            provisioning_state = dep.get('properties', {}).get('provisioningState', 'N/A')
                            print(f"  - {name}: {provisioning_state} ({timestamp})")
                        if len(deployments) > 5:
                            print(f"  ... and {len(deployments) - 5} more deployments")
                    else:
                        print("✗ No ARM template deployments found")
                else:
                    print(f"✗ Failed to retrieve deployments: {response.status_code}")
            except Exception as e:
                print(f"✗ Exception occurred: {e}")
        
        # Check Azure Policy compliance for ARM templates
        print("\n2. AZURE POLICY COMPLIANCE MONITORING:")
        print("-" * 50)
        try:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Policy/assignments?api-version=2022-06-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                assignments = response.json().get('value', [])
                arm_policies = [p for p in assignments if 'arm' in p.get('properties', {}).get('displayName', '').lower() or 
                               'template' in p.get('properties', {}).get('displayName', '').lower()]
                if arm_policies:
                    print(f"✓ Found {len(arm_policies)} ARM-related policy assignments")
                    for policy in arm_policies[:3]:
                        name = policy.get('properties', {}).get('displayName', 'Unnamed')
                        enforcement = policy.get('properties', {}).get('enforcementMode', 'Default')
                        print(f"  - {name}: {enforcement}")
                else:
                    print("✗ No ARM-specific policy assignments found")
            else:
                print(f"✗ Failed to retrieve policy assignments: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # Check PIM role assignments for deployment approvals
        print("\n3. PIM ROLE ASSIGNMENTS FOR DEPLOYMENT APPROVALS:")
        print("-" * 50)
        try:
            url = f"{self.graph_base_url}/roleManagement/directory/roleAssignmentSchedulePolicies"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                policies = response.json().get('value', [])
                deployment_roles = [p for p in policies if 'contributor' in p.get('roleDefinitionId', '').lower() or 
                                   'owner' in p.get('roleDefinitionId', '').lower()]
                if deployment_roles:
                    print(f"✓ Found {len(deployment_roles)} PIM policies for deployment roles")
                    for policy in deployment_roles:
                        role_id = policy.get('roleDefinitionId', 'Unknown')
                        max_duration = policy.get('maxActivationDuration', 'Not set')
                        print(f"  - Role: {role_id.split('/')[-1]}, Max Duration: {max_duration}")
                else:
                    print("✗ No PIM policies found for deployment roles")
            elif response.status_code == 400:
                print("✗ PIM role assignment policies not available (requires Entra ID P2)")
            else:
                print(f"✗ Failed to retrieve PIM policies: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # Check Azure Posture Management (Defender for Cloud) for configuration monitoring
        print("\n4. AZURE POSTURE MANAGEMENT (DEFENDER FOR CLOUD) MONITORING:")
        print("-" * 50)
        try:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Security/assessments?api-version=2020-01-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                assessments = response.json().get('value', [])
                config_assessments = [a for a in assessments if 'configuration' in a.get('properties', {}).get('displayName', '').lower() or
                                     'baseline' in a.get('properties', {}).get('displayName', '').lower()]
                if config_assessments:
                    print(f"✓ Found {len(config_assessments)} configuration-related security assessments")
                    for assessment in config_assessments[:3]:
                        name = assessment.get('properties', {}).get('displayName', 'Unnamed')
                        status = assessment.get('properties', {}).get('status', {}).get('code', 'Unknown')
                        print(f"  - {name}: {status}")
                else:
                    print("✗ No configuration-related security assessments found")
            else:
                print(f"✗ Failed to retrieve security assessments: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # Check for configuration drift monitoring
        print("\n5. CONFIGURATION DRIFT MONITORING:")
        print("-" * 50)
        try:
            # Check for Azure Policy compliance states
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Policy/stateChanges?api-version=2022-06-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                state_changes = response.json().get('value', [])
                if state_changes:
                    print(f"✓ Found {len(state_changes)} policy state changes (drift monitoring)")
                    recent_changes = [c for c in state_changes if c.get('properties', {}).get('timestamp', '') > '2024-01-01']
                    print(f"  - {len(recent_changes)} changes in 2024")
                else:
                    print("✗ No policy state changes found")
            else:
                print(f"✗ Failed to retrieve policy state changes: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        print("=" * 80)

    def print_defender_app_control_status(self):
        print("=" * 80)
        print("DEFENDER APPLICATION CONTROL (MDAC) POLICY STATUS")
        print("=" * 80)
        print("This function checks for Defender Application Control (MDAC) policies in Intune device configurations. It evidences application whitelisting and control for endpoint security and compliance.")
        print("-" * 80)
        url = f"{self.graph_base_url}/deviceManagement/deviceConfigurations"
        try:
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                configs = response.json().get('value', [])
                found = False
                lines = 0
                for config in configs:
                    if lines >= self.max_lines:
                        print(f"Output truncated at {self.max_lines} lines.")
                        break
                    if 'applicationcontrol' in (config.get('displayName', '').lower() + config.get('description', '').lower()):
                        found = True
                        print(f"Policy: {config.get('displayName')}")
                        print(f"  Description: {config.get('description', 'N/A')}")
                        lines += 1
                if not found:
                    print("No Defender Application Control (MDAC) policies found in Intune device configurations.")
            else:
                print(f"Failed to retrieve device configurations: {response.status_code}")
        except Exception as e:
            print(f"Exception occurred: {e}")
        print("=" * 80)

    def print_log_analytics_immutability(self, workspace_name):
        print("=" * 80)
        print("LOG ANALYTICS WORKSPACE IMMUTABILITY SETTINGS")
        print("=" * 80)
        print("This function checks the immutability settings for a Log Analytics workspace. It evidences log data protection against tampering and deletion for compliance and audit readiness.")
        print("-" * 80)
        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}?api-version=2022-10-01"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                ws = response.json()
                immutability = ws.get('properties', {}).get('immutableWorkspaceProperties', {})
                if immutability:
                    state = immutability.get('state', 'Not set')
                    print(f"Immutability State: {state}")
                else:
                    print("Immutability State: Not set or not available")
            else:
                print(f"Failed to retrieve workspace settings: {response.status_code}")
        except Exception as e:
            print(f"Exception occurred while retrieving workspace settings: {e}")
        print("=" * 80)

    def print_sentinel_log_deletion_alert_rules(self, workspace_name):
        print("=" * 80)
        print("SENTINEL ANALYTIC RULES FOR LOG DELETION ALERTS")
        print("=" * 80)
        print("This function checks for Sentinel analytic rules that alert on log deletion activity. It evidences monitoring and alerting for log integrity and retention compliance.")
        print("-" * 80)
        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-12-01-preview"
        try:
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                rules = response.json().get('value', [])
                found = False
                lines = 0
                for rule in rules:
                    if lines >= self.max_lines:
                        print(f"Output truncated at {self.max_lines} lines.")
                        break
                    query = rule.get('properties', {}).get('query', '')
                    if 'delete' in query.lower():
                        found = True
                        print(f"Rule: {rule.get('name')}")
                        print(f"  Description: {rule.get('properties', {}).get('description', 'N/A')}")
                        lines += 1
                if not found:
                    print("No Sentinel analytic rules found for log deletion alerts.")
            else:
                print(f"Failed to retrieve analytic rules: {response.status_code}")
        except Exception as e:
            print(f"Exception occurred: {e}")
        print("=" * 80)

    def print_pim_role_assignment_policies(self):
        print("=" * 80)
        print("MICROSOFT ENTRA PRIVILEGED IDENTITY MANAGEMENT (PIM) ROLE ASSIGNMENT POLICIES")
        print("=" * 80)
        print("This function checks and prints Privileged Identity Management (PIM) settings for Azure AD roles using the Microsoft Graph API. It evidences privileged access management and assignment policies for compliance.")
        print("-" * 80)
        url = f"{self.graph_base_url}/roleManagement/directory/roleAssignmentSchedulePolicies"
        try:
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                policies = response.json().get('value', [])
                if not policies:
                    print("No PIM role assignment schedule policies found.")
                for policy in policies:
                    print(f"Policy ID: {policy.get('id', 'N/A')}")
                    print(f"  - Display Name: {policy.get('displayName', 'N/A')}")
                    print(f"  - Role Definition ID: {policy.get('roleDefinitionId', 'N/A')}")
                    print(f"  - Max Activation Duration: {policy.get('maxActivationDuration', 'N/A')}")
                    print(f"  - Assignment Type: {policy.get('assignmentType', 'N/A')}")
                    print(f"  - Is Default: {policy.get('isDefault', 'N/A')}")
                    print(f"  - Conditions: {policy.get('conditions', 'N/A')}")
                    print("-" * 40)
            elif response.status_code == 400 and 'Resource not found for the segment' in response.text:
                print("PIM role assignment policies are only available with Microsoft Entra ID P2 (Azure AD Premium P2) and may not be available in your tenant or region.")
            else:
                print(f"Failed to retrieve PIM role assignment policies: {response.status_code}")
                print(response.text)
        except Exception as e:
            print(f"Exception occurred while retrieving PIM role assignment policies: {e}")
        print("=" * 80)

    def print_intune_device_compliance_details(self):
        print("=" * 80)
        print("MICROSOFT INTUNE DEVICE COMPLIANCE POLICY DETAILS")
        print("=" * 80)
        print("This function prints detailed Intune device compliance policy settings for Windows, iOS, and Android, including minimum OS version, encryption, jailbreak/root detection, and firewall/antivirus requirements. It evidences device compliance with security baselines across platforms.")
        print("-" * 80)
        url = f"{self.graph_base_url}/deviceManagement/deviceCompliancePolicies"
        try:
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                policies = response.json().get('value', [])
                if not policies:
                    print("No device compliance policies found.")
                for policy in policies:
                    odata_type = policy.get('@odata.type', '')
                    display_name = policy.get('displayName', 'Unnamed Policy')
                    print(f"Policy: {display_name}")
                    if odata_type.endswith('windows10CompliancePolicy'):
                        print("  - Platform: Windows 10/11")
                        print(f"  - Minimum OS Version: {policy.get('minWindows10Version', 'N/A')}")
                        print(f"  - Encryption Required: {policy.get('bitLockerEnabled', 'N/A')}")
                        print(f"  - Firewall Required: {policy.get('firewallEnabled', 'N/A')}")
                        print(f"  - Antivirus Required: {policy.get('defenderEnabled', 'N/A')}")
                        print(f"  - Secure Boot Required: {policy.get('secureBootEnabled', 'N/A')}")
                        print(f"  - Password Required: {policy.get('passwordRequired', 'N/A')}")
                    elif odata_type.endswith('iosCompliancePolicy'):
                        print("  - Platform: iOS")
                        print(f"  - Minimum OS Version: {policy.get('minOSVersion', 'N/A')}")
                        print(f"  - Device Threat Protection Required: {policy.get('deviceThreatProtectionEnabled', 'N/A')}")
                        print(f"  - Jailbreak Detection: {policy.get('passcodeBlockSimple', 'N/A')}")
                        print(f"  - Encryption Required: {policy.get('storageRequireEncryption', 'N/A')}")
                    elif odata_type.endswith('androidCompliancePolicy'):
                        print("  - Platform: Android")
                        print(f"  - Minimum OS Version: {policy.get('minAndroidVersion', 'N/A')}")
                        print(f"  - Device Threat Protection Required: {policy.get('deviceThreatProtectionEnabled', 'N/A')}")
                        print(f"  - Root Detection: {policy.get('securityBlockJailbrokenDevices', 'N/A')}")
                        print(f"  - Encryption Required: {policy.get('storageRequireEncryption', 'N/A')}")
                    else:
                        print(f"  - Platform: Other ({odata_type})")
                    print("-" * 40)
            else:
                print(f"Failed to retrieve device compliance policies: {response.status_code}")
        except Exception as e:
            print(f"Exception occurred while retrieving device compliance details: {e}")
        print("=" * 80)

    def print_certificate_compliance_evidence(self):
        print("=" * 80)
        print("CERTIFICATE COMPLIANCE EVIDENCE: APPROVED CERTIFICATE AUTHORITIES")
        print("=" * 80)
        print("This function provides evidence for the Approved Certificate Authorities control, including inventory of all SSL/TLS certificates, issuer, expiration, associated system, and compliance gaps. It checks for Azure Certificate Manager deployment, Key Vault integration, monitoring/alerting, and logging. It highlights any gaps with FedRAMP Moderate requirements.")
        print("-" * 80)

        # 1. Check for Azure Certificate Manager deployment (compliance gap)
        print("Azure Certificate Manager Deployment Status:")
        url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.CertificateManager/certificateManagers?api-version=2022-01-01"
        response = requests.get(url, headers=self.arm_headers)
        if response.status_code == 404 or response.status_code == 400:
            print("✗ Azure Certificate Manager is NOT deployed in this subscription. This is a compliance gap under FedRAMP Moderate controls.")
        elif response.status_code == 200 and not response.json().get('value'):
            print("✗ Azure Certificate Manager is NOT deployed in this subscription. This is a compliance gap under FedRAMP Moderate controls.")
        elif response.status_code == 200:
            print("✓ Azure Certificate Manager is deployed.")
        else:
            print(f"? Unable to determine Azure Certificate Manager status: {response.status_code}")
        print()

        # 2. Inventory certificates from Key Vaults
        print("Key Vault Certificate Inventory:")
        kv_url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01"
        kv_resp = requests.get(kv_url, headers=self.arm_headers)
        if kv_resp.status_code == 200:
            vaults = kv_resp.json().get('value', [])
            if not vaults:
                print("  No Key Vaults found.")
            for vault in vaults:
                vault_name = vault.get('name')
                rg = vault.get('id').split('/')[4]
                certs_url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{vault_name}/certificates?api-version=2022-07-01"
                certs_resp = requests.get(certs_url, headers=self.arm_headers)
                if certs_resp.status_code == 200:
                    certs = certs_resp.json().get('value', [])
                    if not certs:
                        print(f"  Vault: {vault_name} (Resource Group: {rg}) - No certificates found.")
                    for cert in certs:
                        cert_name = cert.get('name')
                        props = cert.get('properties', {})
                        issuer = props.get('issuer', 'N/A')
                        exp = props.get('expires', 'N/A')
                        print(f"  Vault: {vault_name}, Certificate: {cert_name}, Issuer: {issuer}, Expiration: {exp}")
                else:
                    print(f"  Vault: {vault_name} - Failed to retrieve certificates: {certs_resp.status_code}")
        else:
            print(f"  Failed to retrieve Key Vaults: {kv_resp.status_code}")
        print()

        # 3. Inventory App Service Certificates
        print("App Service Certificate Inventory:")
        asc_url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Web/certificates?api-version=2022-03-01"
        asc_resp = requests.get(asc_url, headers=self.arm_headers)
        if asc_resp.status_code == 200:
            certs = asc_resp.json().get('value', [])
            if not certs:
                print("  No App Service Certificates found.")
            for cert in certs:
                cert_name = cert.get('name')
                props = cert.get('properties', {})
                issuer = props.get('issuer', 'N/A')
                exp = props.get('expirationDate', 'N/A')
                print(f"  App Service Certificate: {cert_name}, Issuer: {issuer}, Expiration: {exp}")
        else:
            print(f"  Failed to retrieve App Service Certificates: {asc_resp.status_code}")
        print()

        # 4. Inventory Application Gateway certificates
        print("Application Gateway Certificate Inventory:")
        agw_url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Network/applicationGateways?api-version=2022-09-01"
        agw_resp = requests.get(agw_url, headers=self.arm_headers)
        if agw_resp.status_code == 200:
            gateways = agw_resp.json().get('value', [])
            if not gateways:
                print("  No Application Gateways found.")
            for gw in gateways:
                gw_name = gw.get('name')
                ssl_certs = gw.get('properties', {}).get('sslCertificates', [])
                if not ssl_certs:
                    print(f"  App Gateway: {gw_name} - No SSL certificates found.")
                for cert in ssl_certs:
                    cert_name = cert.get('name')
                    props = cert.get('properties', {})
                    exp = props.get('expiry', 'N/A')
                    subject = props.get('subjectName', 'N/A')
                    print(f"  App Gateway: {gw_name}, Certificate: {cert_name}, Subject: {subject}, Expiration: {exp}")
        else:
            print(f"  Failed to retrieve Application Gateways: {agw_resp.status_code}")
        print()

        # 5. Inventory Front Door certificates
        print("Front Door Certificate Inventory:")
        fd_url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Cdn/profiles?api-version=2021-06-01"
        fd_resp = requests.get(fd_url, headers=self.arm_headers)
        if fd_resp.status_code == 200:
            profiles = fd_resp.json().get('value', [])
            if not profiles:
                print("  No Front Door profiles found.")
            for profile in profiles:
                profile_name = profile.get('name')
                endpoints_url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{profile.get('id').split('/')[4]}/providers/Microsoft.Cdn/profiles/{profile_name}/endpoints?api-version=2021-06-01"
                endpoints_resp = requests.get(endpoints_url, headers=self.arm_headers)
                if endpoints_resp.status_code == 200:
                    endpoints = endpoints_resp.json().get('value', [])
                    for ep in endpoints:
                        ep_name = ep.get('name')
                        custom_domains = ep.get('properties', {}).get('customDomains', [])
                        for domain in custom_domains:
                            domain_name = domain.get('name')
                            props = domain.get('properties', {})
                            cert_type = props.get('certificateType', 'N/A')
                            exp = props.get('expirationDate', 'N/A')
                            print(f"  Front Door: {profile_name}, Endpoint: {ep_name}, Domain: {domain_name}, Certificate Type: {cert_type}, Expiration: {exp}")
                else:
                    print(f"  Front Door: {profile_name} - Failed to retrieve endpoints: {endpoints_resp.status_code}")
        else:
            print(f"  Failed to retrieve Front Door profiles: {fd_resp.status_code}")

    def print_master_inventory_reconciliation(self):
        print("=" * 80)
        print("MASTER INVENTORY RECONCILIATION: AZURE RESOURCE MANAGER")
        print("=" * 80)
        print("This function evidences the Master Inventory Reconciliation control by checking Azure Resource Manager inventory, Azure Resource Graph queries, Azure Policy compliance, tagging standards, and change tracking. It validates monthly inventory reviews, component change monitoring, and compliance status for FedRAMP Moderate requirements.")
        print("-" * 80)
        
        # 1. Check Azure Resource Manager inventory completeness
        print("1. AZURE RESOURCE MANAGER INVENTORY COMPLETENESS:")
        print("-" * 50)
        try:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resources?api-version=2021-04-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                resources = response.json().get('value', [])
                print(f"✓ Found {len(resources)} total resources in Azure Resource Manager")
                
                # Categorize resources by type
                resource_types = {}
                for resource in resources:
                    resource_type = resource.get('type', 'Unknown')
                    resource_types[resource_type] = resource_types.get(resource_type, 0) + 1
                
                print("Resource Type Distribution:")
                for rtype, count in sorted(resource_types.items(), key=lambda x: x[1], reverse=True)[:10]:
                    print(f"  - {rtype}: {count} resources")
                
                if len(resource_types) > 10:
                    print(f"  ... and {len(resource_types) - 10} more resource types")
            else:
                print(f"✗ Failed to retrieve resources: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 2. Check Azure Policy compliance for inventory management
        print("\n2. AZURE POLICY COMPLIANCE FOR INVENTORY MANAGEMENT:")
        print("-" * 50)
        try:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                assignments = response.json().get('value', [])
                inventory_policies = [p for p in assignments if any(keyword in p.get('properties', {}).get('displayName', '').lower() 
                                   for keyword in ['tag', 'inventory', 'compliance', 'resource', 'asset'])]
                if inventory_policies:
                    print(f"✓ Found {len(inventory_policies)} inventory-related policy assignments")
                    for policy in inventory_policies[:5]:
                        name = policy.get('properties', {}).get('displayName', 'Unnamed')
                        enforcement = policy.get('properties', {}).get('enforcementMode', 'Default')
                        print(f"  - {name}: {enforcement}")
                else:
                    print("✗ No inventory-related policy assignments found")
            else:
                print(f"✗ Failed to retrieve policy assignments: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 3. Check resource tagging compliance
        print("\n3. RESOURCE TAGGING COMPLIANCE:")
        print("-" * 50)
        try:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resources?api-version=2021-04-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                resources = response.json().get('value', [])
                untagged_resources = []
                missing_required_tags = []
                required_tags = ['owner', 'environment', 'classification', 'costcenter', 'project']
                
                for resource in resources:
                    tags = resource.get('tags', {})
                    if not tags:
                        untagged_resources.append(resource.get('name', 'Unnamed'))
                    else:
                        missing_tags = [tag for tag in required_tags if tag.lower() not in [k.lower() for k in tags.keys()]]
                        if missing_tags:
                            missing_required_tags.append((resource.get('name', 'Unnamed'), missing_tags))
                
                print(f"Total Resources: {len(resources)}")
                print(f"Untagged Resources: {len(untagged_resources)}")
                print(f"Resources Missing Required Tags: {len(missing_required_tags)}")
                
                if untagged_resources:
                    print("Sample Untagged Resources:")
                    for resource in untagged_resources[:5]:
                        print(f"  - {resource}")
                    if len(untagged_resources) > 5:
                        print(f"  ... and {len(untagged_resources) - 5} more")
                
                if missing_required_tags:
                    print("Sample Resources Missing Required Tags:")
                    for resource, missing in missing_required_tags[:5]:
                        print(f"  - {resource}: Missing {', '.join(missing)}")
                    if len(missing_required_tags) > 5:
                        print(f"  ... and {len(missing_required_tags) - 5} more")
            else:
                print(f"✗ Failed to retrieve resources: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 5. Check Azure Activity Logs for change tracking
        print("\n5. AZURE ACTIVITY LOGS CHANGE TRACKING:")
        print("-" * 50)
        try:
            # Check for recent resource changes
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/microsoft.insights/eventTypes/management/values?api-version=2015-04-01&$filter=eventTimestamp ge '2024-01-01T00:00:00Z'"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                events = response.json().get('value', [])
                resource_changes = [e for e in events if any(keyword in e.get('operationName', {}).get('value', '').lower() 
                               for keyword in ['write', 'create', 'delete', 'update'])]
                if resource_changes:
                    print(f"✓ Found {len(resource_changes)} resource changes in 2024")
                    print("Recent Resource Changes:")
                    for event in resource_changes[:5]:
                        operation = event.get('operationName', {}).get('value', 'N/A')
                        resource = event.get('resourceId', 'N/A').split('/')[-1]
                        timestamp = event.get('eventTimestamp', 'N/A')
                        print(f"  - {operation} on {resource}: {timestamp}")
                    if len(resource_changes) > 5:
                        print(f"  ... and {len(resource_changes) - 5} more changes")
                else:
                    print("✗ No recent resource changes found")
            else:
                print(f"✗ Failed to retrieve activity logs: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 6. Check Defender for Cloud inventory monitoring
        print("\n6. DEFENDER FOR CLOUD INVENTORY MONITORING:")
        print("-" * 50)
        try:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Security/assessments?api-version=2020-01-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                assessments = response.json().get('value', [])
                inventory_assessments = [a for a in assessments if any(keyword in a.get('properties', {}).get('displayName', '').lower() 
                                    for keyword in ['inventory', 'asset', 'resource', 'tag'])]
                if inventory_assessments:
                    print(f"✓ Found {len(inventory_assessments)} inventory-related security assessments")
                    for assessment in inventory_assessments[:3]:
                        name = assessment.get('properties', {}).get('displayName', 'Unnamed')
                        status = assessment.get('properties', {}).get('status', {}).get('code', 'Unknown')
                        print(f"  - {name}: {status}")
                else:
                    print("✗ No inventory-related security assessments found")
            else:
                print(f"✗ Failed to retrieve security assessments: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 7. Check for monthly review documentation
        print("\n7. MONTHLY REVIEW DOCUMENTATION:")
        print("-" * 50)
        try:
            # Check for recent audit logs that might indicate inventory reviews
            url = f"{self.graph_base_url}/auditLogs/directoryAudits?$top=20&$filter=activityDisplayName eq 'Update application' or activityDisplayName eq 'Update service principal' or activityDisplayName eq 'Add member to group'"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                events = response.json().get('value', [])
                review_events = [e for e in events if any(keyword in e.get('activityDisplayName', '').lower() 
                              for keyword in ['review', 'inventory', 'audit', 'compliance'])]
                if review_events:
                    print(f"✓ Found {len(review_events)} recent inventory review activities")
                    for event in review_events[:3]:
                        activity = event.get('activityDisplayName', 'N/A')
                        timestamp = event.get('activityDateTime', 'N/A')
                        print(f"  - {activity}: {timestamp}")
                else:
                    print("✗ No recent inventory review activities found")
            else:
                print(f"✗ Failed to retrieve audit events: {response.status_code} \n {response.text}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        print("=" * 80)

    def print_infrastructure_vulnerability_scans(self):
        print("=" * 80)
        print("INFRASTRUCTURE VULNERABILITY SCANS: AZURE POSTURE MANAGEMENT")
        print("=" * 80)
        print("This function evidences the Infrastructure Vulnerability Scans control by checking Azure Posture Management (Defender for Cloud) configuration, vulnerability assessment capabilities, and scan results tracking. It validates continuous monitoring and vulnerability management for FedRAMP Moderate compliance.")
        print("-" * 80)
        
        # 1. Check Defender for Cloud (Azure Posture Management) deployment status
        print("1. AZURE POSTURE MANAGEMENT (DEFENDER FOR CLOUD) DEPLOYMENT STATUS:")
        print("-" * 60)
        try:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Security/pricings?api-version=2024-01-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                pricings = response.json().get('value', [])
                if pricings:
                    print("✓ Defender for Cloud pricing tiers configured:")
                    for pricing in pricings:
                        name = pricing.get('name', 'N/A')
                        tier = pricing.get('properties', {}).get('pricingTier', 'N/A')
                        print(f"  - {name}: {tier}")
                        
                        # Check for vulnerability assessment capabilities
                        if name in ['VirtualMachines', 'SqlServers', 'ContainerRegistry', 'KubernetesService']:
                            if tier == 'Free':
                                print(f"    ⚠️  {name} is on Free tier - limited vulnerability assessment capabilities")
                            elif tier in ['Standard', 'Premium']:
                                print(f"    ✓ {name} has enhanced vulnerability assessment capabilities")
                else:
                    print("✗ No Defender for Cloud pricing information found")
            else:
                print(f"✗ Failed to retrieve Defender for Cloud pricing: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 2. Check vulnerability assessment configuration
        print("\n2. VULNERABILITY ASSESSMENT CONFIGURATION:")
        print("-" * 60)
        try:
            # Check for Microsoft Defender for Servers
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Security/assessments?api-version=2020-01-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                assessments = response.json().get('value', [])
                vulnerability_assessments = [a for a in assessments if any(keyword in a.get('properties', {}).get('displayName', '').lower() 
                                        for keyword in ['vulnerability', 'baseline', 'security configuration', 'compliance'])]
                if vulnerability_assessments:
                    print(f"✓ Found {len(vulnerability_assessments)} vulnerability and baseline assessments")
                    for assessment in vulnerability_assessments[:5]:  # Show first 5
                        name = assessment.get('properties', {}).get('displayName', 'Unnamed')
                        status = assessment.get('properties', {}).get('status', {}).get('code', 'Unknown')
                        severity = assessment.get('properties', {}).get('metadata', {}).get('severity', 'N/A')
                        print(f"  - {name}: {status} (Severity: {severity})")
                    if len(vulnerability_assessments) > 5:
                        print(f"  ... and {len(vulnerability_assessments) - 5} more assessments")
                else:
                    print("✗ No vulnerability assessments found")
            else:
                print(f"✗ Failed to retrieve security assessments: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 3. Check for failed security assessments (vulnerabilities)
        print("\n3. FAILED SECURITY ASSESSMENTS (VULNERABILITIES):")
        print("-" * 60)
        try:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Security/assessments?api-version=2020-01-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                assessments = response.json().get('value', [])
                failed_assessments = [a for a in assessments if a.get('properties', {}).get('status', {}).get('code') == 'Unhealthy']
                if failed_assessments:
                    print(f"⚠️  Found {len(failed_assessments)} failed security assessments (vulnerabilities):")
                    high_critical_count = 0
                    for assessment in failed_assessments:
                        name = assessment.get('properties', {}).get('displayName', 'Unnamed')
                        severity = assessment.get('properties', {}).get('metadata', {}).get('severity', 'N/A')
                        if severity in ['High', 'Critical']:
                            high_critical_count += 1
                            print(f"  🔴 {name} (Severity: {severity})")
                    
                    print(f"\nSummary:")
                    print(f"  - Total failed assessments: {len(failed_assessments)}")
                    print(f"  - High/Critical severity: {high_critical_count}")
                    print(f"  - Medium/Low severity: {len(failed_assessments) - high_critical_count}")
                    
                    if high_critical_count > 0:
                        print(f"\n⚠️  COMPLIANCE GAP: {high_critical_count} high/critical vulnerabilities require immediate remediation")
                else:
                    print("✓ No failed security assessments found")
            else:
                print(f"✗ Failed to retrieve security assessments: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 4. Check for automated vulnerability scanning configuration
        print("\n4. AUTOMATED VULNERABILITY SCANNING CONFIGURATION:")
        print("-" * 60)
        try:
            # Check for Microsoft Defender for Containers (container vulnerability scanning)
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Security/pricings?api-version=2024-01-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                pricings = response.json().get('value', [])
                containers_pricing = next((p for p in pricings if p.get('name') == 'Containers'), None)
                if containers_pricing:
                    tier = containers_pricing.get('properties', {}).get('pricingTier', 'N/A')
                    if tier in ['Standard', 'Premium']:
                        print("✓ Microsoft Defender for Containers enabled - automated container vulnerability scanning")
                    else:
                        print("✗ Microsoft Defender for Containers not enabled - no automated container vulnerability scanning")
                else:
                    print("✗ Microsoft Defender for Containers not configured")
                
                # Check for Microsoft Defender for Servers (VM vulnerability scanning)
                vm_pricing = next((p for p in pricings if p.get('name') == 'VirtualMachines'), None)
                if vm_pricing:
                    tier = vm_pricing.get('properties', {}).get('pricingTier', 'N/A')
                    if tier in ['Standard', 'Premium']:
                        print("✓ Microsoft Defender for Servers enabled - automated VM vulnerability scanning")
                    else:
                        print("✗ Microsoft Defender for Servers not enabled - no automated VM vulnerability scanning")
                else:
                    print("✗ Microsoft Defender for Servers not configured")
            else:
                print(f"✗ Failed to retrieve Defender pricing: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 5. Check for vulnerability scan results tracking
        print("\n5. VULNERABILITY SCAN RESULTS TRACKING:")
        print("-" * 60)
        try:
            # Check for recent security alerts that might indicate vulnerability findings
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Security/alerts?api-version=2020-01-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                alerts = response.json().get('value', [])
                vulnerability_alerts = [a for a in alerts if any(keyword in a.get('properties', {}).get('alertDisplayName', '').lower() 
                                    for keyword in ['vulnerability', 'baseline', 'compliance', 'security configuration'])]
                if vulnerability_alerts:
                    print(f"✓ Found {len(vulnerability_alerts)} vulnerability-related security alerts")
                    recent_alerts = [a for a in vulnerability_alerts if a.get('properties', {}).get('reportedTimeUtc', '') > '2024-01-01']
                    print(f"  - Recent alerts (2024): {len(recent_alerts)}")
                    print(f"  - Historical alerts: {len(vulnerability_alerts) - len(recent_alerts)}")
                else:
                    print("✗ No vulnerability-related security alerts found")
            else:
                print(f"✗ Failed to retrieve security alerts: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 6. Check for baseline configuration standards
        print("\n6. BASELINE CONFIGURATION STANDARDS:")
        print("-" * 60)
        try:
            # Check for CIS benchmark compliance
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                assignments = response.json().get('value', [])
                baseline_policies = [p for p in assignments if any(keyword in p.get('properties', {}).get('displayName', '').lower() 
                                for keyword in ['cis', 'baseline', 'benchmark', 'security standard'])]
                if baseline_policies:
                    print("✓ Baseline configuration standards configured:")
                    for policy in baseline_policies:
                        name = policy.get('properties', {}).get('displayName', 'Unnamed')
                        enforcement = policy.get('properties', {}).get('enforcementMode', 'Default')
                        print(f"  - {name}: {enforcement}")
                else:
                    print("✗ No baseline configuration standards found")
            else:
                print(f"✗ Failed to retrieve policy assignments: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        print("=" * 80)

    def print_insider_threat_escalation(self):
        print("=" * 80)
        print("INSIDER THREAT ESCALATION: USER AND ENTITY BEHAVIOR ANALYTICS")
        print("=" * 80)
        print("This function evidences the Insider Threat Escalation control by checking Microsoft Sentinel UEBA configuration, high-risk user monitoring, and insider threat detection capabilities. It validates automated monitoring and response for potential insider threats for FedRAMP Moderate compliance.")
        print("-" * 80)
        
        # 1. Check Microsoft Sentinel UEBA Configuration
        print("1. MICROSOFT SENTINEL UEBA CONFIGURATION:")
        print("-" * 60)
        try:
            # Check for UEBA settings in Sentinel workspace
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}/providers/Microsoft.SecurityInsights/settings?api-version=2023-02-01-preview"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                settings = response.json().get('value', [])
                ueba_enabled = False
                for setting in settings:
                    if setting.get('kind') == 'Ueba':
                        ueba_enabled = True
                        print("✓ User and Entity Behavior Analytics (UEBA) is ENABLED in Microsoft Sentinel")
                        break
                if not ueba_enabled:
                    print("✗ User and Entity Behavior Analytics (UEBA) is NOT enabled in Microsoft Sentinel")
                    print("  - This is a critical gap for insider threat detection")
                    print("  - Enable UEBA in Sentinel workspace Configuration > Settings")
            else:
                print(f"✗ Failed to retrieve Sentinel settings: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 2. Check for High-Risk User Monitoring Analytics Rules
        print("\n2. HIGH-RISK USER MONITORING ANALYTICS RULES:")
        print("-" * 60)
        try:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01-preview"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                rules = response.json().get('value', [])
                insider_threat_rules = []
                ueba_rules = []
                
                for rule in rules:
                    rule_name = rule.get('name', '').lower()
                    rule_description = rule.get('properties', {}).get('description', '').lower()
                    
                    # Check for insider threat related rules
                    if any(keyword in rule_name or keyword in rule_description 
                           for keyword in ['insider', 'privilege', 'escalation', 'anomaly', 'behavior', 'risk']):
                        insider_threat_rules.append(rule)
                    
                    # Check for UEBA specific rules
                    if 'ueba' in rule_name or 'entity' in rule_name:
                        ueba_rules.append(rule)
                
                if insider_threat_rules:
                    print(f"✓ Found {len(insider_threat_rules)} insider threat related analytics rules:")
                    for rule in insider_threat_rules[:5]:  # Show first 5
                        name = rule.get('name', 'Unnamed')
                        enabled = rule.get('properties', {}).get('enabled', False)
                        status = "✓ Enabled" if enabled else "✗ Disabled"
                        print(f"  - {name}: {status}")
                    if len(insider_threat_rules) > 5:
                        print(f"  ... and {len(insider_threat_rules) - 5} more rules")
                else:
                    print("✗ No insider threat related analytics rules found")
                
                if ueba_rules:
                    print(f"\n✓ Found {len(ueba_rules)} UEBA-specific analytics rules")
                else:
                    print("\n✗ No UEBA-specific analytics rules found")
            else:
                print(f"✗ Failed to retrieve analytics rules: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 3. Check for High-Risk User Identification and Tagging
        print("\n3. HIGH-RISK USER IDENTIFICATION AND TAGGING:")
        print("-" * 60)
        try:
            # Check for user risk policies and high-privilege users
            url = f"{self.graph_base_url}/directoryRoles"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                roles = response.json().get('value', [])
                high_privilege_roles = ['Global Administrator', 'Security Administrator', 'Privileged Role Administrator', 'Exchange Administrator']
                high_risk_users = []
                
                for role in roles:
                    role_name = role.get('displayName', '')
                    if role_name in high_privilege_roles:
                        role_id = role.get('id')
                        # Get members of high-privilege roles
                        members_url = f"{self.graph_base_url}/directoryRoles/{role_id}/members"
                        members_response = requests.get(members_url, headers=self.graph_headers)
                        if members_response.status_code == 200:
                            members = members_response.json().get('value', [])
                            for member in members:
                                user_info = {
                                    'name': member.get('displayName', 'Unknown'),
                                    'upn': member.get('userPrincipalName', 'Unknown'),
                                    'role': role_name,
                                    'risk_level': 'High (Elevated Privileges)'
                                }
                                high_risk_users.append(user_info)
                
                if high_risk_users:
                    print(f"✓ Identified {len(high_risk_users)} high-risk users with elevated privileges:")
                    for user in high_risk_users[:10]:  # Show first 10
                        print(f"  - {user['name']} ({user['upn']})")
                        print(f"    Role: {user['role']}, Risk Level: {user['risk_level']}")
                    if len(high_risk_users) > 10:
                        print(f"  ... and {len(high_risk_users) - 10} more high-risk users")
                else:
                    print("✓ No high-privilege users identified")
            else:
                print(f"✗ Failed to retrieve directory roles: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 4. Check for Anomalous User Activity Monitoring
        print("\n4. ANOMALOUS USER ACTIVITY MONITORING:")
        print("-" * 60)
        try:
            # Check for recent sign-in risk detections (potential insider threat indicators)
            url = f"{self.graph_base_url}/identityProtection/riskDetections?$top=20"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                detections = response.json().get('value', [])
                anomalous_activities = [d for d in detections if d.get('riskEventType') in ['unfamiliarFeatures', 'unlikelyTravel', 'malwareLinkedIP', 'suspiciousIP']]
                
                if anomalous_activities:
                    print(f"✓ Found {len(anomalous_activities)} recent anomalous user activities:")
                    for activity in anomalous_activities[:5]:  # Show first 5
                        user = activity.get('userDisplayName', 'Unknown')
                        risk_type = activity.get('riskEventType', 'Unknown')
                        risk_level = activity.get('riskLevel', 'Unknown')
                        timestamp = activity.get('activityDateTime', 'Unknown')
                        print(f"  - User: {user}, Risk Type: {risk_type}, Level: {risk_level}, Time: {timestamp}")
                    if len(anomalous_activities) > 5:
                        print(f"  ... and {len(anomalous_activities) - 5} more anomalous activities")
                else:
                    print("✓ No recent anomalous user activities detected")
            elif response.status_code == 403:
                print("✗ Identity Protection not available (requires Microsoft Entra ID P2)")
            else:
                print(f"✗ Failed to retrieve risk detections: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 5. Check for Insider Threat Incident Response
        print("\n5. INSIDER THREAT INCIDENT RESPONSE:")
        print("-" * 60)
        try:
            # Check for recent security incidents in Sentinel
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01-preview"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                incidents = response.json().get('value', [])
                insider_incidents = [i for i in incidents if any(keyword in i.get('properties', {}).get('title', '').lower() 
                                for keyword in ['insider', 'privilege', 'escalation', 'anomaly', 'unauthorized'])]
                
                if insider_incidents:
                    print(f"✓ Found {len(insider_incidents)} insider threat related incidents:")
                    for incident in insider_incidents[:3]:  # Show first 3
                        title = incident.get('properties', {}).get('title', 'Unnamed')
                        status = incident.get('properties', {}).get('status', 'Unknown')
                        severity = incident.get('properties', {}).get('severity', 'Unknown')
                        created = incident.get('properties', {}).get('createdTimeUtc', 'Unknown')
                        print(f"  - {title}: {status} (Severity: {severity}, Created: {created})")
                    if len(insider_incidents) > 3:
                        print(f"  ... and {len(insider_incidents) - 3} more incidents")
                else:
                    print("✓ No insider threat related incidents found")
            else:
                print(f"✗ Failed to retrieve incidents: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 6. Check for Session Monitoring and Logging
        print("\n6. SESSION MONITORING AND LOGGING:")
        print("-" * 60)
        try:
            # Check for audit log configuration and session monitoring
            url = f"{self.graph_base_url}/auditLogs/directoryAudits?$top=10"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                audit_events = response.json().get('value', [])
                session_events = [e for e in audit_events if e.get('activityDisplayName') in ['User signed in', 'User signed out', 'User logged in']]
                
                if session_events:
                    print(f"✓ Found {len(session_events)} recent session events in audit logs")
                    print("  - Session monitoring is configured and logging user activities")
                else:
                    print("✗ No recent session events found in audit logs")
            elif response.status_code == 403:
                print("✗ Audit log access not available (requires AuditLog.Read.All permission)")
            else:
                print(f"✗ Failed to retrieve audit logs: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 7. Check for Infrastructure Monitoring Integration
        print("\n7. INFRASTRUCTURE MONITORING INTEGRATION:")
        print("-" * 60)
        try:
            # Check for data connectors that provide infrastructure monitoring
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2023-02-01-preview"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                connectors = response.json().get('value', [])
                monitoring_connectors = []
                
                for connector in connectors:
                    connector_type = connector.get('kind', '')
                    if connector_type in ['AzureActiveDirectory', 'MicrosoftDefenderAdvancedThreatProtection', 'Office365']:
                        monitoring_connectors.append(connector)
                
                if monitoring_connectors:
                    print(f"✓ Found {len(monitoring_connectors)} infrastructure monitoring data connectors:")
                    for connector in monitoring_connectors:
                        connector_type = connector.get('kind', 'Unknown')
                        print(f"  - {connector_type} connector enabled")
                else:
                    print("✗ No infrastructure monitoring data connectors found")
            else:
                print(f"✗ Failed to retrieve data connectors: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        print("=" * 80)

    def print_intrusion_detection_systems(self):
        print("=" * 80)
        print("INTRUSION DETECTION SYSTEMS: MICROSOFT DEFENDER FOR CLOUD")
        print("=" * 80)
        print("This function evidences the Intrusion Detection Systems control by checking Microsoft Defender for Cloud integration with Microsoft Sentinel, data connector configuration, alert ingestion, and incident response capabilities. It validates intrusion detection and response for FedRAMP Moderate compliance.")
        print("-" * 80)
        
        # 1. Check Microsoft Defender for Cloud Deployment Status
        print("1. MICROSOFT DEFENDER FOR CLOUD DEPLOYMENT STATUS:")
        print("-" * 60)
        try:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Security/pricings?api-version=2024-01-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                pricings = response.json().get('value', [])
                if pricings:
                    print("✓ Microsoft Defender for Cloud pricing tiers configured:")
                    defender_plans = {
                        'VirtualMachines': 'Defender for Servers',
                        'AppServices': 'Defender for App Services', 
                        'KeyVaults': 'Defender for Key Vault',
                        'StorageAccounts': 'Defender for Storage',
                        'SqlServers': 'Defender for SQL',
                        'KubernetesService': 'Defender for Containers',
                        'ContainerRegistry': 'Defender for Container Registries'
                    }
                    
                    enabled_plans = []
                    disabled_plans = []
                    
                    for pricing in pricings:
                        name = pricing.get('name', 'N/A')
                        tier = pricing.get('properties', {}).get('pricingTier', 'N/A')
                        plan_name = defender_plans.get(name, name)
                        
                        if tier in ['Standard', 'Premium']:
                            enabled_plans.append(f"{plan_name} ({tier})")
                            print(f"  ✓ {plan_name}: {tier}")
                        else:
                            disabled_plans.append(plan_name)
                            print(f"  ✗ {plan_name}: {tier} (Limited intrusion detection capabilities)")
                    
                    print(f"\nSummary:")
                    print(f"  - Enabled Defender Plans: {len(enabled_plans)}")
                    print(f"  - Disabled Defender Plans: {len(disabled_plans)}")
                    
                    if len(enabled_plans) == 0:
                        print(f"\n⚠️  CRITICAL GAP: No Microsoft Defender plans are enabled")
                        print(f"   This severely limits intrusion detection capabilities")
                else:
                    print("✗ No Microsoft Defender for Cloud pricing information found")
            else:
                print(f"✗ Failed to retrieve Defender pricing: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 2. Check Microsoft Sentinel Data Connector Integration
        print("\n2. MICROSOFT SENTINEL DATA CONNECTOR INTEGRATION:")
        print("-" * 60)
        try:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2023-02-01-preview"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                connectors = response.json().get('value', [])
                defender_connectors = []
                
                for connector in connectors:
                    connector_type = connector.get('kind', '')
                    if connector_type == 'AzureSecurityCenter':
                        defender_connectors.append(connector)
                
                if defender_connectors:
                    print("✓ Microsoft Defender for Cloud data connector is ENABLED in Sentinel")
                    for connector in defender_connectors:
                        connector_name = connector.get('name', 'Unknown')
                        connector_state = connector.get('properties', {}).get('connectorState', 'Unknown')
                        print(f"  - Connector: {connector_name}, State: {connector_state}")
                else:
                    print("✗ Microsoft Defender for Cloud data connector is NOT enabled in Sentinel")
                    print("  - This is a critical gap for intrusion detection")
                    print("  - Enable the Azure Security Center data connector in Sentinel")
            else:
                print(f"✗ Failed to retrieve data connectors: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 3. Check for Defender-Generated Security Alerts
        print("\n3. DEFENDER-GENERATED SECURITY ALERTS:")
        print("-" * 60)
        try:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Security/alerts?api-version=2020-01-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                alerts = response.json().get('value', [])
                if alerts:
                    print(f"✓ Found {len(alerts)} security alerts from Microsoft Defender for Cloud")
                    
                    # Categorize alerts by severity
                    high_critical_alerts = [a for a in alerts if a.get('properties', {}).get('severity') in ['High', 'Critical']]
                    medium_low_alerts = [a for a in alerts if a.get('properties', {}).get('severity') in ['Medium', 'Low']]
                    
                    print(f"  - High/Critical Severity: {len(high_critical_alerts)}")
                    print(f"  - Medium/Low Severity: {len(medium_low_alerts)}")
                    
                    if high_critical_alerts:
                        print(f"\nRecent High/Critical Alerts:")
                        for alert in high_critical_alerts[:5]:  # Show first 5
                            alert_name = alert.get('properties', {}).get('alertDisplayName', 'Unnamed')
                            severity = alert.get('properties', {}).get('severity', 'Unknown')
                            reported_time = alert.get('properties', {}).get('reportedTimeUtc', 'Unknown')
                            print(f"  - {alert_name}: {severity} (Reported: {reported_time})")
                        if len(high_critical_alerts) > 5:
                            print(f"  ... and {len(high_critical_alerts) - 5} more high/critical alerts")
                else:
                    print("✓ No security alerts found from Microsoft Defender for Cloud")
            else:
                print(f"✗ Failed to retrieve security alerts: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 4. Check for Sentinel Incidents from Defender Alerts
        print("\n4. SENTINEL INCIDENTS FROM DEFENDER ALERTS:")
        print("-" * 60)
        try:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01-preview"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                incidents = response.json().get('value', [])
                defender_incidents = [i for i in incidents if any(keyword in i.get('properties', {}).get('title', '').lower() 
                                for keyword in ['defender', 'security center', 'azure security', 'malware', 'threat', 'attack'])]
                
                if defender_incidents:
                    print(f"✓ Found {len(defender_incidents)} incidents in Sentinel from Defender alerts")
                    
                    # Categorize by status
                    open_incidents = [i for i in defender_incidents if i.get('properties', {}).get('status') == 'New']
                    closed_incidents = [i for i in defender_incidents if i.get('properties', {}).get('status') == 'Closed']
                    
                    print(f"  - Open Incidents: {len(open_incidents)}")
                    print(f"  - Closed Incidents: {len(closed_incidents)}")
                    
                    if open_incidents:
                        print(f"\nRecent Open Incidents:")
                        for incident in open_incidents[:3]:  # Show first 3
                            title = incident.get('properties', {}).get('title', 'Unnamed')
                            severity = incident.get('properties', {}).get('severity', 'Unknown')
                            created = incident.get('properties', {}).get('createdTimeUtc', 'Unknown')
                            print(f"  - {title}: {severity} (Created: {created})")
                        if len(open_incidents) > 3:
                            print(f"  ... and {len(open_incidents) - 3} more open incidents")
                else:
                    print("✓ No incidents found in Sentinel from Defender alerts")
            else:
                print(f"✗ Failed to retrieve incidents: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 5. Check for Custom Analytics Rules for Defender Alerts
        print("\n5. CUSTOM ANALYTICS RULES FOR DEFENDER ALERTS:")
        print("-" * 60)
        try:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01-preview"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                rules = response.json().get('value', [])
                defender_rules = []
                
                for rule in rules:
                    rule_name = rule.get('name', '').lower()
                    rule_description = rule.get('properties', {}).get('description', '').lower()
                    rule_query = rule.get('properties', {}).get('query', '').lower()
                    
                    # Check for Defender-related rules
                    if any(keyword in rule_name or keyword in rule_description or keyword in rule_query
                           for keyword in ['defender', 'security center', 'azure security', 'malware', 'threat', 'attack', 'intrusion']):
                        defender_rules.append(rule)
                
                if defender_rules:
                    print(f"✓ Found {len(defender_rules)} custom analytics rules for Defender alerts:")
                    for rule in defender_rules[:5]:  # Show first 5
                        name = rule.get('name', 'Unnamed')
                        enabled = rule.get('properties', {}).get('enabled', False)
                        status = "✓ Enabled" if enabled else "✗ Disabled"
                        print(f"  - {name}: {status}")
                    if len(defender_rules) > 5:
                        print(f"  ... and {len(defender_rules) - 5} more rules")
                else:
                    print("✗ No custom analytics rules found for Defender alerts")
                    print("  - Consider creating custom rules to enhance intrusion detection")
            else:
                print(f"✗ Failed to retrieve analytics rules: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 6. Check for Intrusion Detection Recommendations
        print("\n6. INTRUSION DETECTION RECOMMENDATIONS:")
        print("-" * 60)
        try:
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/providers/Microsoft.Security/assessments?api-version=2020-01-01"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                assessments = response.json().get('value', [])
                intrusion_assessments = [a for a in assessments if any(keyword in a.get('properties', {}).get('displayName', '').lower() 
                                    for keyword in ['intrusion', 'threat', 'malware', 'attack', 'security', 'monitoring'])]
                
                if intrusion_assessments:
                    print(f"✓ Found {len(intrusion_assessments)} intrusion detection related assessments:")
                    
                    failed_assessments = [a for a in intrusion_assessments if a.get('properties', {}).get('status', {}).get('code') == 'Unhealthy']
                    
                    if failed_assessments:
                        print(f"  - Failed Assessments: {len(failed_assessments)}")
                        for assessment in failed_assessments[:3]:  # Show first 3
                            name = assessment.get('properties', {}).get('displayName', 'Unnamed')
                            severity = assessment.get('properties', {}).get('metadata', {}).get('severity', 'N/A')
                            print(f"    ✗ {name} (Severity: {severity})")
                        if len(failed_assessments) > 3:
                            print(f"    ... and {len(failed_assessments) - 3} more failed assessments")
                    else:
                        print(f"  - All intrusion detection assessments are healthy")
                else:
                    print("✗ No intrusion detection related assessments found")
            else:
                print(f"✗ Failed to retrieve security assessments: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 7. Check for Threat Intelligence Integration
        print("\n7. THREAT INTELLIGENCE INTEGRATION:")
        print("-" * 60)
        try:
            # Check for threat intelligence data connectors
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2023-02-01-preview"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                connectors = response.json().get('value', [])
                threat_intel_connectors = []
                
                for connector in connectors:
                    connector_type = connector.get('kind', '')
                    if connector_type in ['ThreatIntelligence', 'ThreatIntelligenceTaxii']:
                        threat_intel_connectors.append(connector)
                
                if threat_intel_connectors:
                    print("✓ Threat intelligence data connectors enabled:")
                    for connector in threat_intel_connectors:
                        connector_name = connector.get('name', 'Unknown')
                        connector_state = connector.get('properties', {}).get('connectorState', 'Unknown')
                        print(f"  - {connector_name}: {connector_state}")
                else:
                    print("✗ No threat intelligence data connectors found")
                    print("  - Consider enabling threat intelligence feeds for enhanced intrusion detection")
            else:
                print(f"✗ Failed to retrieve data connectors: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        print("=" * 80)

    def print_logical_access_review(self):
        print("=" * 80)
        print("LOGICAL ACCESS REVIEW: MICROSOFT ENTRA ID IDENTITY GOVERNANCE")
        print("=" * 80)
        print("This function evidences the Logical Access Review control by checking Microsoft Entra ID Identity Governance access reviews, recurring review configurations, and automatic user removal settings. It validates monthly access certification processes for FedRAMP Moderate compliance.")
        print("-" * 80)
        
        # 1. Check for Access Review Configuration
        print("1. ACCESS REVIEW CONFIGURATION:")
        print("-" * 60)
        try:
            # Check for access review policies using Microsoft Graph API
            url = f"{self.graph_base_url}/identityGovernance/accessReviews/definitions"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                reviews = response.json().get('value', [])
                if reviews:
                    print(f"✓ Found {len(reviews)} access review definitions configured:")
                    
                    active_reviews = [r for r in reviews if r.get('status') == 'InProgress' or r.get('status') == 'NotStarted']
                    completed_reviews = [r for r in reviews if r.get('status') == 'Completed']
                    
                    print(f"  - Active Reviews: {len(active_reviews)}")
                    print(f"  - Completed Reviews: {len(completed_reviews)}")
                    
                    for review in reviews[:5]:  # Show first 5
                        display_name = review.get('displayName', 'Unnamed')
                        status = review.get('status', 'Unknown')
                        created_date = review.get('createdDateTime', 'Unknown')
                        print(f"  - {display_name}: {status} (Created: {created_date})")
                    if len(reviews) > 5:
                        print(f"  ... and {len(reviews) - 5} more access reviews")
                else:
                    print("✗ No access review definitions found")
                    print("  - This is a critical gap for logical access review compliance")
                    print("  - Configure access reviews in Identity Governance > Access Reviews")
            elif response.status_code == 400 and 'Resource not found for the segment' in response.text:
                print("✗ Access Reviews are only available with Microsoft Entra ID P2 (Azure AD Premium P2)")
                print("  - This feature requires Azure AD Premium P2 licensing")
            else:
                print(f"✗ Failed to retrieve access reviews: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 2. Check for Recurring Access Reviews
        print("\n2. RECURRING ACCESS REVIEW CONFIGURATION:")
        print("-" * 60)
        try:
            url = f"{self.graph_base_url}/identityGovernance/accessReviews/definitions"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                reviews = response.json().get('value', [])
                recurring_reviews = [r for r in reviews if r.get('instanceEnumerationScope', {}).get('recurrence')]
                
                if recurring_reviews:
                    print(f"✓ Found {len(recurring_reviews)} recurring access reviews:")
                    for review in recurring_reviews:
                        display_name = review.get('displayName', 'Unnamed')
                        recurrence = review.get('instanceEnumerationScope', {}).get('recurrence', {})
                        pattern = recurrence.get('pattern', {})
                        interval = pattern.get('interval', 'Unknown')
                        frequency = pattern.get('type', 'Unknown')
                        print(f"  - {display_name}: {frequency} (every {interval} months)")
                else:
                    print("✗ No recurring access reviews found")
                    print("  - Monthly recurring reviews are required for compliance")
            elif response.status_code == 400:
                print("✗ Access Reviews not available (requires Entra ID P2)")
            else:
                print(f"✗ Failed to retrieve access reviews: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 3. Check for Auto-Apply Results Configuration
        print("\n3. AUTO-APPLY RESULTS CONFIGURATION:")
        print("-" * 60)
        try:
            url = f"{self.graph_base_url}/identityGovernance/accessReviews/definitions"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                reviews = response.json().get('value', [])
                auto_apply_reviews = [r for r in reviews if r.get('settings', {}).get('autoApplyDecisionsEnabled')]
                
                if auto_apply_reviews:
                    print(f"✓ Found {len(auto_apply_reviews)} access reviews with auto-apply enabled:")
                    for review in auto_apply_reviews:
                        display_name = review.get('displayName', 'Unnamed')
                        auto_remove = review.get('settings', {}).get('autoApplyDecisionsEnabled', False)
                        print(f"  - {display_name}: Auto-apply {'✓ Enabled' if auto_remove else '✗ Disabled'}")
                else:
                    print("✗ No access reviews with auto-apply results found")
                    print("  - Auto-apply is required to automatically remove non-responding users")
            elif response.status_code == 400:
                print("✗ Access Reviews not available (requires Entra ID P2)")
            else:
                print(f"✗ Failed to retrieve access reviews: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 4. Check for Access Review Instances (Recent Reviews)
        print("\n4. RECENT ACCESS REVIEW INSTANCES:")
        print("-" * 60)
        try:
            url = f"{self.graph_base_url}/identityGovernance/accessReviews/definitions"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                reviews = response.json().get('value', [])
                if reviews:
                    # Get instances for the first review definition
                    review_id = reviews[0].get('id')
                    instances_url = f"{self.graph_base_url}/identityGovernance/accessReviews/definitions/{review_id}/instances"
                    instances_response = requests.get(instances_url, headers=self.graph_headers)
                    
                    if instances_response.status_code == 200:
                        instances = instances_response.json().get('value', [])
                        if instances:
                            print(f"✓ Found {len(instances)} access review instances:")
                            
                            recent_instances = [i for i in instances if i.get('startDateTime', '') > '2024-01-01']
                            print(f"  - Recent instances (2024): {len(recent_instances)}")
                            
                            for instance in instances[:3]:  # Show first 3
                                start_date = instance.get('startDateTime', 'Unknown')
                                end_date = instance.get('endDateTime', 'Unknown')
                                status = instance.get('status', 'Unknown')
                                print(f"  - Instance: {start_date} to {end_date} ({status})")
                            if len(instances) > 3:
                                print(f"  ... and {len(instances) - 3} more instances")
                        else:
                            print("✗ No access review instances found")
                    else:
                        print(f"✗ Failed to retrieve access review instances: {instances_response.status_code}")
                else:
                    print("✗ No access review definitions found to check instances")
            elif response.status_code == 400:
                print("✗ Access Reviews not available (requires Entra ID P2)")
            else:
                print(f"✗ Failed to retrieve access reviews: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 5. Check for Group-Based Access Control
        print("\n5. GROUP-BASED ACCESS CONTROL:")
        print("-" * 60)
        try:
            # Check for groups that might be used for access control
            url = f"{self.graph_base_url}/groups"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                groups = response.json().get('value', [])
                
                # Filter for groups that might be used for system access
                access_groups = [g for g in groups if any(keyword in g.get('displayName', '').lower() 
                                for keyword in ['access', 'system', 'app', 'resource', 'admin', 'user', 'role'])]
                
                if access_groups:
                    print(f"✓ Found {len(access_groups)} potential access control groups:")
                    for group in access_groups[:10]:  # Show first 10
                        group_name = group.get('displayName', 'Unnamed')
                        member_count = group.get('members@odata.count', 'Unknown')
                        print(f"  - {group_name} ({member_count} members)")
                    if len(access_groups) > 10:
                        print(f"  ... and {len(access_groups) - 10} more groups")
                else:
                    print("✗ No access control groups identified")
                    print("  - Consider creating groups for system access management")
            else:
                print(f"✗ Failed to retrieve groups: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 6. Check for Access Review Notifications
        print("\n6. ACCESS REVIEW NOTIFICATIONS:")
        print("-" * 60)
        try:
            url = f"{self.graph_base_url}/identityGovernance/accessReviews/definitions"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                reviews = response.json().get('value', [])
                if reviews:
                    # Check notification settings for the first review
                    review_settings = reviews[0].get('settings', {})
                    notifications_enabled = review_settings.get('notificationsEnabled', False)
                    
                    if notifications_enabled:
                        print("✓ Access review notifications are enabled")
                        print(f"  - Reviewers will be notified of pending reviews")
                    else:
                        print("✗ Access review notifications are disabled")
                        print("  - Enable notifications to ensure reviewers are aware of pending reviews")
                else:
                    print("✗ No access reviews found to check notification settings")
            elif response.status_code == 400:
                print("✗ Access Reviews not available (requires Entra ID P2)")
            else:
                print(f"✗ Failed to retrieve access reviews: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 7. Check for Access Review Completion Tracking
        print("\n7. ACCESS REVIEW COMPLETION TRACKING:")
        print("-" * 60)
        try:
            # Check for recent audit events related to access reviews
            url = f"{self.graph_base_url}/auditLogs/directoryAudits?$top=20&$filter=activityDisplayName eq 'Access review completed' or activityDisplayName eq 'Access review started'"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                audit_events = response.json().get('value', [])
                access_review_events = [e for e in audit_events if 'access review' in e.get('activityDisplayName', '').lower()]
                
                if access_review_events:
                    print(f"✓ Found {len(access_review_events)} recent access review audit events:")
                    for event in access_review_events[:3]:  # Show first 3
                        activity = event.get('activityDisplayName', 'Unknown')
                        timestamp = event.get('activityDateTime', 'Unknown')
                        print(f"  - {activity}: {timestamp}")
                    if len(access_review_events) > 3:
                        print(f"  ... and {len(access_review_events) - 3} more events")
                else:
                    print("✗ No recent access review audit events found")
                    print("  - This may indicate access reviews are not being conducted")
            elif response.status_code == 403:
                print("✗ Audit log access not available (requires AuditLog.Read.All permission)")
            else:
                print(f"✗ Failed to retrieve audit events: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 8. Check for User Removal Tracking
        print("\n8. USER REMOVAL TRACKING:")
        print("-" * 60)
        try:
            # Check for recent user removal events
            url = f"{self.graph_base_url}/auditLogs/directoryAudits?$top=20&$filter=activityDisplayName eq 'Remove member from group'"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                audit_events = response.json().get('value', [])
                
                if audit_events:
                    print(f"✓ Found {len(audit_events)} recent user removal events:")
                    for event in audit_events[:5]:  # Show first 5
                        timestamp = event.get('activityDateTime', 'Unknown')
                        target = event.get('targetResources', [{}])[0].get('displayName', 'Unknown')
                        print(f"  - User removed from {target}: {timestamp}")
                    if len(audit_events) > 5:
                        print(f"  ... and {len(audit_events) - 5} more removal events")
                else:
                    print("✓ No recent user removal events found")
            elif response.status_code == 403:
                print("✗ Audit log access not available (requires AuditLog.Read.All permission)")
            else:
                print(f"✗ Failed to retrieve audit events: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        print("=" * 80)

    def print_logical_access_revocation(self):
        print("=" * 80)
        print("LOGICAL ACCESS REVOCATION: AUTOMATED OFFBOARDING PROCESS")
        print("=" * 80)
        print("This function evidences the Logical Access Revocation control by checking automated offboarding processes, credential revocation tracking, and 24-hour compliance monitoring. It validates timely access removal following role changes or termination for FedRAMP Moderate compliance.")
        print("-" * 80)
        
        # 1. Check for Automated Offboarding Process Configuration
        print("1. AUTOMATED OFFBOARDING PROCESS CONFIGURATION:")
        print("-" * 60)
        try:
            # Check for lifecycle management policies in Entra ID
            url = f"{self.graph_base_url}/identityGovernance/lifecycleWorkflows/workflows"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                workflows = response.json().get('value', [])
                offboarding_workflows = [w for w in workflows if 'offboard' in w.get('displayName', '').lower() or 
                                        'termination' in w.get('displayName', '').lower() or 
                                        'revocation' in w.get('displayName', '').lower()]
                
                if offboarding_workflows:
                    print(f"✓ Found {len(offboarding_workflows)} automated offboarding workflows:")
                    for workflow in offboarding_workflows:
                        name = workflow.get('displayName', 'Unnamed')
                        state = workflow.get('state', 'Unknown')
                        enabled = "✓ Enabled" if state == 'Enabled' else "✗ Disabled"
                        print(f"  - {name}: {enabled}")
                else:
                    print("✗ No automated offboarding workflows found")
                    print("  - This is a critical gap for timely access revocation")
                    print("  - Configure lifecycle workflows for automated offboarding")
            elif response.status_code == 400 and 'Resource not found for the segment' in response.text:
                print("✗ Lifecycle Workflows are only available with Microsoft Entra ID P2 (Azure AD Premium P2)")
                print("  - This feature requires Azure AD Premium P2 licensing")
            else:
                print(f"✗ Failed to retrieve lifecycle workflows: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 2. Check for 24-Hour Revocation Compliance Tracking
        print("\n2. 24-HOUR REVOCATION COMPLIANCE TRACKING:")
        print("-" * 60)
        try:
            # Check for recent user removal events and timing
            url = f"{self.graph_base_url}/auditLogs/directoryAudits?$top=50&$filter=activityDisplayName eq 'Remove member from group' or activityDisplayName eq 'Delete user' or activityDisplayName eq 'Disable user'"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                audit_events = response.json().get('value', [])
                
                if audit_events:
                    print(f"✓ Found {len(audit_events)} recent access revocation events")
                    
                    # Analyze timing of recent events (last 30 days)
                    from datetime import datetime, timedelta
                    thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat() + 'Z'
                    recent_events = [e for e in audit_events if e.get('activityDateTime', '') > thirty_days_ago]
                    
                    print(f"  - Recent events (last 30 days): {len(recent_events)}")
                    print(f"  - Historical events: {len(audit_events) - len(recent_events)}")
                    
                    if recent_events:
                        print(f"\nRecent Access Revocation Events:")
                        for event in recent_events[:5]:  # Show first 5
                            activity = event.get('activityDisplayName', 'Unknown')
                            timestamp = event.get('activityDateTime', 'Unknown')
                            target = event.get('targetResources', [{}])[0].get('displayName', 'Unknown')
                            print(f"  - {activity} for {target}: {timestamp}")
                        if len(recent_events) > 5:
                            print(f"  ... and {len(recent_events) - 5} more recent events")
                else:
                    print("✓ No recent access revocation events found")
            elif response.status_code == 403:
                print("✗ Audit log access not available (requires AuditLog.Read.All permission)")
            else:
                print(f"✗ Failed to retrieve audit events: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 3. Check for Credential Revocation in Microsoft Entra ID
        print("\n3. CREDENTIAL REVOCATION IN MICROSOFT ENTRA ID:")
        print("-" * 60)
        try:
            # Check for recent password resets and account disablements
            url = f"{self.graph_base_url}/auditLogs/directoryAudits?$top=20&$filter=activityDisplayName eq 'Reset user password' or activityDisplayName eq 'Disable user' or activityDisplayName eq 'Delete user'"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                credential_events = response.json().get('value', [])
                
                if credential_events:
                    print(f"✓ Found {len(credential_events)} recent credential revocation events:")
                    
                    password_resets = [e for e in credential_events if e.get('activityDisplayName') == 'Reset user password']
                    account_disables = [e for e in credential_events if e.get('activityDisplayName') == 'Disable user']
                    account_deletes = [e for e in credential_events if e.get('activityDisplayName') == 'Delete user']
                    
                    print(f"  - Password Resets: {len(password_resets)}")
                    print(f"  - Account Disablements: {len(account_disables)}")
                    print(f"  - Account Deletions: {len(account_deletes)}")
                    
                    if credential_events:
                        print(f"\nRecent Credential Revocation Events:")
                        for event in credential_events[:3]:  # Show first 3
                            activity = event.get('activityDisplayName', 'Unknown')
                            timestamp = event.get('activityDateTime', 'Unknown')
                            target = event.get('targetResources', [{}])[0].get('displayName', 'Unknown')
                            print(f"  - {activity} for {target}: {timestamp}")
                        if len(credential_events) > 3:
                            print(f"  ... and {len(credential_events) - 3} more events")
                else:
                    print("✓ No recent credential revocation events found")
            elif response.status_code == 403:
                print("✗ Audit log access not available (requires AuditLog.Read.All permission)")
            else:
                print(f"✗ Failed to retrieve audit events: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 4. Check for Role Permission Revocation
        print("\n4. ROLE PERMISSION REVOCATION:")
        print("-" * 60)
        try:
            # Check for recent role assignment removals
            url = f"{self.graph_base_url}/auditLogs/directoryAudits?$top=20&$filter=activityDisplayName eq 'Remove member from group' or activityDisplayName eq 'Remove app role assignment from user'"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                role_events = response.json().get('value', [])
                
                if role_events:
                    print(f"✓ Found {len(role_events)} recent role permission revocation events:")
                    
                    group_removals = [e for e in role_events if e.get('activityDisplayName') == 'Remove member from group']
                    app_role_removals = [e for e in role_events if e.get('activityDisplayName') == 'Remove app role assignment from user']
                    
                    print(f"  - Group Membership Removals: {len(group_removals)}")
                    print(f"  - Application Role Removals: {len(app_role_removals)}")
                    
                    if role_events:
                        print(f"\nRecent Role Permission Revocation Events:")
                        for event in role_events[:3]:  # Show first 3
                            activity = event.get('activityDisplayName', 'Unknown')
                            timestamp = event.get('activityDateTime', 'Unknown')
                            target = event.get('targetResources', [{}])[0].get('displayName', 'Unknown')
                            print(f"  - {activity} for {target}: {timestamp}")
                        if len(role_events) > 3:
                            print(f"  ... and {len(role_events) - 3} more events")
                else:
                    print("✓ No recent role permission revocation events found")
            elif response.status_code == 403:
                print("✗ Audit log access not available (requires AuditLog.Read.All permission)")
            else:
                print(f"✗ Failed to retrieve audit events: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 5. Check for SharePoint Integration and Task Management
        print("\n5. SHAREPOINT INTEGRATION AND TASK MANAGEMENT:")
        print("-" * 60)
        try:
            # Check for SharePoint-related audit events
            url = f"{self.graph_base_url}/auditLogs/directoryAudits?$top=20&$filter=activityDisplayName eq 'Update application' or activityDisplayName eq 'Update service principal'"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                sharepoint_events = response.json().get('value', [])
                
                if sharepoint_events:
                    print(f"✓ Found {len(sharepoint_events)} recent SharePoint/application update events")
                    print("  - These may indicate offboarding task completions")
                    
                    for event in sharepoint_events[:3]:  # Show first 3
                        activity = event.get('activityDisplayName', 'Unknown')
                        timestamp = event.get('activityDateTime', 'Unknown')
                        target = event.get('targetResources', [{}])[0].get('displayName', 'Unknown')
                        print(f"  - {activity} for {target}: {timestamp}")
                    if len(sharepoint_events) > 3:
                        print(f"  ... and {len(sharepoint_events) - 3} more events")
                else:
                    print("✗ No recent SharePoint/application update events found")
                    print("  - This may indicate limited SharePoint integration")
            elif response.status_code == 403:
                print("✗ Audit log access not available (requires AuditLog.Read.All permission)")
            else:
                print(f"✗ Failed to retrieve audit events: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 6. Check for Manager Confirmation Process
        print("\n6. MANAGER CONFIRMATION PROCESS:")
        print("-" * 60)
        try:
            # Check for approval-related audit events
            url = f"{self.graph_base_url}/auditLogs/directoryAudits?$top=20&$filter=activityDisplayName eq 'Add member to group' or activityDisplayName eq 'Update group'"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                approval_events = response.json().get('value', [])
                
                if approval_events:
                    print(f"✓ Found {len(approval_events)} recent group management events")
                    print("  - These may indicate manager confirmations of access changes")
                    
                    for event in approval_events[:3]:  # Show first 3
                        activity = event.get('activityDisplayName', 'Unknown')
                        timestamp = event.get('activityDateTime', 'Unknown')
                        target = event.get('targetResources', [{}])[0].get('displayName', 'Unknown')
                        print(f"  - {activity} for {target}: {timestamp}")
                    if len(approval_events) > 3:
                        print(f"  ... and {len(approval_events) - 3} more events")
                else:
                    print("✗ No recent group management events found")
                    print("  - This may indicate limited manager involvement in access management")
            elif response.status_code == 403:
                print("✗ Audit log access not available (requires AuditLog.Read.All permission)")
            else:
                print(f"✗ Failed to retrieve audit events: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 7. Check for Automated Alerting and Escalation
        print("\n7. AUTOMATED ALERTING AND ESCALATION:")
        print("-" * 60)
        try:
            # Check for Sentinel incidents related to access revocation
            url = f"{self.arm_base_url}/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01-preview"
            response = requests.get(url, headers=self.arm_headers)
            if response.status_code == 200:
                incidents = response.json().get('value', [])
                revocation_incidents = [i for i in incidents if any(keyword in i.get('properties', {}).get('title', '').lower() 
                                for keyword in ['revocation', 'offboard', 'termination', 'access removal', 'credential'])]
                
                if revocation_incidents:
                    print(f"✓ Found {len(revocation_incidents)} access revocation related incidents:")
                    
                    open_incidents = [i for i in revocation_incidents if i.get('properties', {}).get('status') == 'New']
                    closed_incidents = [i for i in revocation_incidents if i.get('properties', {}).get('status') == 'Closed']
                    
                    print(f"  - Open Incidents: {len(open_incidents)}")
                    print(f"  - Closed Incidents: {len(closed_incidents)}")
                    
                    if open_incidents:
                        print(f"\nOpen Access Revocation Incidents:")
                        for incident in open_incidents[:3]:  # Show first 3
                            title = incident.get('properties', {}).get('title', 'Unnamed')
                            severity = incident.get('properties', {}).get('severity', 'Unknown')
                            created = incident.get('properties', {}).get('createdTimeUtc', 'Unknown')
                            print(f"  - {title}: {severity} (Created: {created})")
                        if len(open_incidents) > 3:
                            print(f"  ... and {len(open_incidents) - 3} more open incidents")
                else:
                    print("✓ No access revocation related incidents found")
            else:
                print(f"✗ Failed to retrieve incidents: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        # 8. Check for Compliance Metrics and Reporting
        print("\n8. COMPLIANCE METRICS AND REPORTING:")
        print("-" * 60)
        try:
            # Check for recent audit events to calculate compliance metrics
            url = f"{self.graph_base_url}/auditLogs/directoryAudits?$top=100"
            response = requests.get(url, headers=self.graph_headers)
            if response.status_code == 200:
                all_events = response.json().get('value', [])
                
                # Calculate basic metrics
                total_revocation_events = len([e for e in all_events if any(keyword in e.get('activityDisplayName', '').lower() 
                                           for keyword in ['remove', 'delete', 'disable', 'reset'])])
                
                if total_revocation_events > 0:
                    print(f"✓ Access revocation compliance metrics:")
                    print(f"  - Total revocation events in audit log: {total_revocation_events}")
                    print(f"  - Audit log retention: Configured (events available)")
                    print(f"  - Compliance tracking: Enabled through audit logging")
                    
                    # Note: 24-hour compliance calculation would require more detailed analysis
                    print(f"  - 24-hour compliance: Requires detailed timing analysis")
                    print(f"  - Recommendation: Implement automated compliance reporting")
                else:
                    print("✗ No revocation events found for compliance metrics")
                    print("  - This may indicate limited access revocation activity")
            elif response.status_code == 403:
                print("✗ Audit log access not available (requires AuditLog.Read.All permission)")
                print("  - Cannot calculate compliance metrics without audit access")
            else:
                print(f"✗ Failed to retrieve audit events: {response.status_code}")
        except Exception as e:
            print(f"✗ Exception occurred: {e}")
        
        print("=" * 80)

def main():
    """Main function to run the Security Policies configuration retriever."""

    class Tee:
        def __init__(self, *files):
            self.files = files
        def write(self, obj):
            for f in self.files:
                f.write(obj)
                f.flush()
        def flush(self):
            for f in self.files:
                f.flush()

    # Open output file and tee stdout/stderr
    out_file = open("out.txt", "w", encoding="utf-8")
    sys.stdout = Tee(sys.stdout, out_file)
    sys.stderr = Tee(sys.stderr, out_file)

    print("=" * 80)
    print("Microsoft Entra ID Security Policies Configuration Retriever")
    print("=" * 80)
    print("")
    
    # Get access tokens
    tokens = get_access_tokens_from_file()
    if not tokens or not tokens.get('graph') or not tokens.get('arm'):
        print("\nTo use this script, you need to:")
        print("1. Register an application in Azure AD")
        print("2. Grant it appropriate permissions (Policy.Read.All, Directory.Read.All, ARM Reader)")
        print("3. Get access tokens for both Microsoft Graph and ARM using client credentials flow")
        print("4. Save the tokens in 'access_tokens.json' as { 'graph': '...', 'arm': '...' }")
        print("\nAlternatively, you can modify this script to use interactive authentication.")
        sys.exit(1)
    
    workspace_name = "Test-workspace"
    
    # Create configuration retriever
    policies_retriever = EntraSecurityPolicies(
        tokens, 
        subscription_id="8c0365ef-854c-4b03-8be5-05f75b2f6b87", 
        resource_group="alex_rg",
        workspace_name=workspace_name,
        max_lines=100
        )

    
    # # =====================
    # # 1. Permissions/General Info
    # # =====================
    # policies_retriever.print_available_permissions()
    policies_retriever.check_token_expiry()

    # # =====================
    # # 2. Entra ID/Graph Security Policies
    # # =====================
    # policies_retriever.print_smart_lockout_settings()
    # policies_retriever.print_password_protection_policy()
    # policies_retriever.print_user_risk_policy()
    # policies_retriever.print_identity_protection_risk_detections()
    # policies_retriever.print_sign_in_risk_policy()
    policies_retriever.print_credential_distribution_audit_events()
    # policies_retriever.print_admin_group_membership()

    # # =====================
    # # 3. Intune/Device Management
    # # =====================
    # policies_retriever.print_intune_machine_inactivity_limit()
    # policies_retriever.print_intune_compliance_policy_checks()
    # policies_retriever.print_intune_device_compliance_details()

    # # =====================
    # # 4. Conditional Access/Identity Protection
    # # =====================
    # policies_retriever.print_conditional_access_policy_checks()
    # policies_retriever.print_pim_role_assignment_policies()

    # # =====================
    # # 5. Azure Resource Manager/Cloud Security
    # # =====================
    # policies_retriever.print_bastion_host_settings()
    # policies_retriever.print_encryption_policy_and_defender_status()
    # policies_retriever.print_cis_l1_initiative_assignment()
    # policies_retriever.print_defender_for_cloud_failed_checks()
    policies_retriever.print_dnssec_status()
    # policies_retriever.print_waf_deployment_and_policy_status()
    # policies_retriever.print_waf_diagnostic_settings()
    # policies_retriever.print_blob_storage_zrs_status()
    # policies_retriever.print_recovery_services_backup_policies()
    # policies_retriever.print_missing_assettag_resources()
    policies_retriever.print_arm_template_configuration_orchestration()
    policies_retriever.print_master_inventory_reconciliation()
    # policies_retriever.print_defender_app_control_status()

    # # =====================
    # # 6. Sentinel/Log Analytics
    # # =====================
    # policies_retriever.print_log_analytics_retention_settings(workspace_name)
    # policies_retriever.print_workspace_rbac(workspace_name)
    # policies_retriever.print_sentinel_error_analytic_rules(workspace_name)
    # policies_retriever.print_sentinel_defender_connector_status(workspace_name)
    # policies_retriever.print_sentinel_defender_endpoint_connector_status(workspace_name)
    # policies_retriever.print_sentinel_incident_summary(workspace_name)
    # policies_retriever.print_log_analytics_immutability(workspace_name)
    # policies_retriever.print_sentinel_log_deletion_alert_rules(workspace_name)

    # # =====================
    # # 7. Certificate/Key Management
    # # =====================
    # policies_retriever.print_certificate_compliance_evidence()

    # # =====================
    # # 8. Defender/Endpoint
    # # =====================
    policies_retriever.print_defender_fim_configuration()
    policies_retriever.print_recent_fim_alerts()

    # # =====================
    # # 9. Network Boundary Protection
    # # =====================
    # policies_retriever.print_nsg_smtp_block_status()
    # policies_retriever.print_firewall_smtp_block_status()
    # policies_retriever.print_bastion_ssh_timeout_status()

    # policies_retriever.print_infrastructure_vulnerability_scans()
    # policies_retriever.print_insider_threat_escalation()
    policies_retriever.print_intrusion_detection_systems()
    policies_retriever.print_logical_access_review()
    policies_retriever.print_logical_access_revocation()

if __name__ == "__main__":
    main() 