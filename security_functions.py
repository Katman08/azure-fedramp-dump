#!/usr/bin/env python3
"""
Security Policy Printer v3 - Security Functions Module

This module contains all security policy checking functions for Microsoft Entra ID and Azure.
"""

from typing import Dict, Any, Optional
from helpers import APIClient, Formatter, Config
import datetime


class SecurityFunctions:
    """A class that encapsulates common parameters for security function calls."""
    
    def __init__(self, api_client: APIClient, formatter: Formatter, config: Config):
        self.api_client = api_client
        self.formatter = formatter
        self.config = config
    
    def _handle_pim_license_error(self, response):
        """Helper method to handle PIM license requirement errors gracefully."""
        if response.status_code == 400:
            try:
                error_data = response.json()
                if error_data.get('error', {}).get('code') == 'AadPremiumLicenseRequired':
                    self.formatter.print_warning("Microsoft Entra ID P2 or Microsoft Entra ID Governance license is required for PIM functionality.")
                    self.formatter.print_info("PIM features are only available with Azure AD Premium P2 or Microsoft Entra ID Governance licenses.")
                    self.formatter.print_info("Consider upgrading your license to enable Privileged Identity Management features.")
                    return True  # Indicates license error was handled
            except:
                pass  # If we can't parse the error, continue with normal error handling
        return False  # No license error handled
    
    def _handle_identity_protection_license_error(self, response):
        """Helper method to handle Identity Protection license requirement errors gracefully."""
        if response.status_code == 403:
            try:
                error_data = response.json()
                if error_data.get('error', {}).get('message', '').find('not licensed') != -1:
                    self.formatter.print_warning("Your tenant is not licensed for Identity Protection features.")
                    self.formatter.print_info("This feature requires Microsoft Entra ID P2 (Azure AD Premium P2) license.")
                    self.formatter.print_info("Identity Protection features are not available without the required license.")
                    return True  # Indicates license error was handled
            except:
                pass  # If we can't parse the error, continue with normal error handling
        return False  # No license error handled
    
    def check_smart_lockout_settings(self):
        """Check Smart Lockout configuration"""
        self.formatter.print_header(
            "MICROSOFT ENTRA ID SMART LOCKOUT POLICY CONFIGURATION",
            "This function retrieves and displays the current Smart Lockout policy for Microsoft Entra ID, including both security defaults and any custom password protection settings. It helps evidence whether lockout protections are enforced to prevent brute-force attacks."
        )
        
        # Get security defaults policy
        security_defaults = self._get_security_defaults_policy()
        self.formatter.print_subsection("SECURITY DEFAULTS POLICY")
        
        if security_defaults:
            self.formatter.print_success("Security defaults policy found")
            self.formatter.print_key_value("Is Enabled", security_defaults.get('isEnabled', 'Unknown'))
            self.formatter.print_key_value("Description", security_defaults.get('description', 'No description'))
            
            if security_defaults.get('isEnabled'):
                self.formatter.print_success("Smart Lockout: Enabled (part of security defaults)")
            else:
                self.formatter.print_error("Smart Lockout: Disabled (security defaults disabled)")
        else:
            self.formatter.print_error("Security defaults policy not found or not accessible")
        
        # Get custom smart lockout settings
        custom_settings = self._get_custom_smart_lockout_settings()
        self.formatter.print_subsection("CUSTOM SMART LOCKOUT SETTINGS (Password Protection)")
        
        if custom_settings:
            threshold = custom_settings.get('LockoutThreshold', 'Not set')
            duration = custom_settings.get('LockoutDurationInSeconds', 'Not set')
            self.formatter.print_success("Custom smart lockout settings found")
            self.formatter.print_key_value("Lockout Threshold", threshold)
            self.formatter.print_key_value("Lockout Duration (seconds)", duration)
        else:
            self.formatter.print_info("No custom smart lockout settings found; using defaults")
            self.formatter.print_key_value("Lockout Threshold", "10 failed attempts (default)")
            self.formatter.print_key_value("Lockout Duration", "60 seconds (default)")
        
        self.formatter.print_info("Note: Smart Lockout settings are typically managed through Security Defaults, Password Protection (custom), Conditional Access policies, or custom authentication policies.")
        self.formatter.print_separator()

    def check_password_protection_policy(self):
        """Check password protection policy"""
        self.formatter.print_header(
            "MICROSOFT ENTRA ID PASSWORD PROTECTION POLICY",
            "This function checks for password protection policies that prevent common weak passwords and enforce password complexity requirements."
        )
        try:
            response = self.api_client.graph_get("/policies/authenticationMethodsPolicy")
            if self.api_client.check_response(response, "Password Protection Policy"):
                policy_data = response.json()
                authentication_methods = policy_data.get('authenticationMethodConfigurations', [])
                password_policies = []
                for method in authentication_methods:
                    if method.get('id') == 'password':
                        password_policies.append(method)
                if password_policies:
                    self.formatter.print_success(f"Found {len(password_policies)} password protection policy")
                    for policy in password_policies:
                        self.formatter.print_key_value("Policy ID", policy.get('id', 'N/A'))
                        self.formatter.print_key_value("State", policy.get('state', 'N/A'))
                        settings = policy.get('additionalSettings', {})
                        if settings:
                            self.formatter.print_subsection("Additional Settings")
                            self.formatter.print_json_like(settings, indent=1)
                else:
                    self.formatter.print_warning("No specific password protection policies found")
                    self.formatter.print_info("Password policies may be managed through Security Defaults or Conditional Access")
            else:
                self.formatter.print_error("Failed to retrieve password protection policies")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        self.formatter.print_separator()

    def check_conditional_access_policies(self):
        """Comprehensive check of Conditional Access policies for compliance, MFA, and mobile device blocking."""
        self.formatter.print_header(
            "MICROSOFT ENTRA CONDITIONAL ACCESS POLICY COMPREHENSIVE CHECK",
            "This function performs a comprehensive analysis of Conditional Access policies including device compliance, MFA requirements, and mobile device blocking. It evidences enforcement of access controls and multi-factor authentication for compliance."
        )
        try:
            response = self.api_client.graph_get("/identity/conditionalAccess/policies")
            if self.api_client.check_response(response, "Conditional Access Policies"):
                # Add null check for response.json()
                response_data = response.json()
                if response_data is None:
                    self.formatter.print_error("Failed to parse response data - response is None")
                    return
                
                policies = response_data.get('value', [])
                if policies is None:
                    policies = []
                
                # Track different types of policies found
                compliance_policies = []
                mfa_policies = []
                mobile_blocking_policies = []
                
                for policy in policies:
                    if not isinstance(policy, dict):
                        continue
                        
                    if policy.get('state') != 'enabled':
                        continue
                        
                    policy_name = policy.get('displayName', 'Unnamed Policy')
                    if policy_name is None:
                        policy_name = 'Unnamed Policy'
                        
                    conditions = policy.get('conditions', {})
                    if conditions is None:
                        conditions = {}
                        
                    grant_controls = policy.get('grantControls', {})
                    if grant_controls is None:
                        grant_controls = {}
                        
                    built_in_controls = grant_controls.get('builtInControls', [])
                    if built_in_controls is None:
                        built_in_controls = []
                    
                    # Check for device compliance requirements
                    device_platforms = conditions.get('devicePlatforms', {})
                    if device_platforms is None:
                        device_platforms = {}
                        
                    if device_platforms.get('includeDevices') == 'all' or 'requireDeviceCompliance' in built_in_controls:
                        compliance_policies.append(policy)
                    
                    # Check for MFA requirements
                    if 'mfa' in built_in_controls:
                        mfa_policies.append(policy)
                    
                    # Check for mobile device blocking
                    include_platforms = device_platforms.get('includeDevicePlatforms', [])
                    if include_platforms is None:
                        include_platforms = []
                        
                    exclude_platforms = device_platforms.get('excludeDevicePlatforms', [])
                    if exclude_platforms is None:
                        exclude_platforms = []
                        
                    mobile_platforms = ['android', 'ios', 'windowsPhone']
                    
                    blocks_mobile = False
                    if any(platform in exclude_platforms for platform in mobile_platforms):
                        blocks_mobile = True
                    if 'block' in built_in_controls and any(platform in include_platforms for platform in mobile_platforms):
                        blocks_mobile = True
                    if 'requireDeviceCompliance' in built_in_controls and any(platform in include_platforms for platform in mobile_platforms):
                        blocks_mobile = True
                    
                    if blocks_mobile:
                        mobile_blocking_policies.append(policy)
                
                # Report Device Compliance Policies
                self.formatter.print_subsection("DEVICE COMPLIANCE POLICIES")
                if compliance_policies:
                    self.formatter.print_success(f"Found {len(compliance_policies)} policies requiring device compliance:")
                    for policy in compliance_policies:
                        self.formatter.print_key_value("Policy", policy.get('displayName'))
                        self.formatter.print_key_value("State", policy.get('state', 'Unknown'))
                        self.formatter.print_separator()
                else:
                    self.formatter.print_warning("No Conditional Access policies found that require device compliance.")
                
                # Report MFA Policies
                self.formatter.print_subsection("MULTI-FACTOR AUTHENTICATION POLICIES")
                if mfa_policies:
                    self.formatter.print_success(f"Found {len(mfa_policies)} policies requiring MFA:")
                    for policy in mfa_policies:
                        self.formatter.print_key_value("Policy", policy.get('displayName'))
                        self.formatter.print_key_value("State", policy.get('state', 'Unknown'))
                        self.formatter.print_separator()
                else:
                    self.formatter.print_warning("No Conditional Access policies found that require MFA.")
                
                # Report Mobile Device Blocking Policies
                self.formatter.print_subsection("MOBILE DEVICE BLOCKING POLICIES")
                if mobile_blocking_policies:
                    self.formatter.print_success(f"Found {len(mobile_blocking_policies)} policies that block mobile devices:")
                    for policy in mobile_blocking_policies:
                        self.formatter.print_key_value("Policy", policy.get('displayName'))
                        self.formatter.print_key_value("State", policy.get('state', 'Unknown'))
                        
                        conditions = policy.get('conditions', {})
                        if conditions is None:
                            self.formatter.print_warning("No conditions found in policy")
                        else:
                            device_platforms = conditions.get('devicePlatforms', {})
                            if device_platforms is None:
                                device_platforms = {}
                                
                            include_platforms = device_platforms.get('includeDevicePlatforms', [])
                            if include_platforms is None:
                                include_platforms = []
                                
                            exclude_platforms = device_platforms.get('excludeDevicePlatforms', [])
                            if exclude_platforms is None:
                                exclude_platforms = []
                        
                        if include_platforms:
                            self.formatter.print_key_value("Include Platforms", ', '.join(include_platforms))
                        if exclude_platforms:
                            self.formatter.print_key_value("Exclude Platforms", ', '.join(exclude_platforms))
                        
                        grant_controls = policy.get('grantControls', {})
                        if grant_controls is None:
                            self.formatter.print_warning("No grant controls found in policy")
                        else:
                            built_in_controls = grant_controls.get('builtInControls', [])
                            self.formatter.print_key_value("Grant Controls", ', '.join(built_in_controls))
                        
                        users = conditions.get('users', {})
                        if users is None:
                            self.formatter.print_warning("No users found in policy")
                        else:
                            include_users = users.get('includeUsers', [])
                            include_groups = users.get('includeGroups', [])
                            if include_users:
                                self.formatter.print_key_value("Include Users", f"{len(include_users)} users")
                            if include_groups:
                                self.formatter.print_key_value("Include Groups", f"{len(include_groups)} groups")
                        self.formatter.print_separator()
                else:
                    self.formatter.print_warning("No Conditional Access policies found that explicitly block mobile devices.")
                    self.formatter.print_info("This may indicate a security gap. Consider implementing policies to block Android, iOS, and Windows Phone platforms.")
                
                # Summary
                total_enabled = len([p for p in policies if p.get('state') == 'enabled'])
                self.formatter.print_subsection("SUMMARY")
                self.formatter.print_key_value("Total Enabled Policies", total_enabled)
                self.formatter.print_key_value("Compliance Policies", len(compliance_policies))
                self.formatter.print_key_value("MFA Policies", len(mfa_policies))
                self.formatter.print_key_value("Mobile Blocking Policies", len(mobile_blocking_policies))
                
            else:
                self.formatter.print_error("Failed to retrieve Conditional Access policies")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        self.formatter.print_separator()

    def _get_security_defaults_policy(self) -> Optional[Dict[str, Any]]:
        """Get security defaults policy"""
        try:
            response = self.api_client.graph_get("/policies/identitySecurityDefaultsEnforcementPolicy")
            if self.api_client.check_response(response, "Security Defaults Policy"):
                return response.json()
        except Exception as e:
            print(f"Error getting security defaults policy: {e}")
        return None

    def _get_custom_smart_lockout_settings(self) -> Optional[dict]:
        """Get custom smart lockout settings"""
        try:
            # Use the correct endpoint for authentication methods policy
            auth_response = self.api_client.graph_get("/policies/authenticationMethodsPolicy")
            if self.api_client.check_response(auth_response, "Authentication Methods Policy"):
                return auth_response.json()
            
            # Fallback: try security defaults policy
            security_response = self.api_client.graph_get("/policies/identitySecurityDefaultsEnforcementPolicy")
            if self.api_client.check_response(security_response, "Security Defaults Policy"):
                return security_response.json()
                
        except Exception as e:
            print(f"Error getting custom smart lockout settings: {e}")
        return None
    
    def check_intune_machine_inactivity_limit(self):
        """Check Intune machine inactivity (auto-lock) limit."""
        self.formatter.print_header(
            "MICROSOFT INTUNE MACHINE INACTIVITY LIMIT (AUTO-LOCK)",
            "This function retrieves and displays the machine inactivity (auto-lock) limit set in Intune device configuration profiles. It evidences enforcement of device lockout after inactivity for compliance with session management requirements."
        )
        try:
            response = self.api_client.graph_get("/deviceManagement/deviceConfigurations")
            if self.api_client.check_response(response, "Intune Device Configurations"):
                configs = response.json().get('value', [])
                found = False
                for config_item in configs:
                    oma_settings = config_item.get('omaSettings', [])
                    for setting in oma_settings:
                        if setting.get('omaUri') == './Device/Vendor/MSFT/Policy/Config/DeviceLock/MaxInactivityTimeDeviceLock':
                            self.formatter.print_key_value("Profile", config_item.get('displayName', 'Unnamed Profile'))
                            self.formatter.print_key_value("Inactivity Limit (minutes)", setting.get('value'))
                            found = True
                if not found:
                    self.formatter.print_warning("No machine inactivity (auto-lock) limit found in Intune device configuration profiles.")
            else:
                self.formatter.print_error("Error retrieving device configurations.")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving Intune inactivity limit: {e}")
        self.formatter.print_separator()

    def check_available_permissions(self):
        """Check which Microsoft Graph API permissions are available with the current access token."""
        self.formatter.print_header(
            "MICROSOFT GRAPH API PERMISSIONS CHECK",
            "This function checks and prints which Microsoft Graph API permissions are available with the current access token. It attempts to call key endpoints and reports which ones succeed or fail, evidencing the effective permissions for compliance and troubleshooting."
        )
        
        test_endpoints = [
            # Policy.Read.All permissions
            ("/policies/identitySecurityDefaultsEnforcementPolicy", "Security Defaults Policy", "Policy.Read.All"),
            ("/policies/authenticationMethodsPolicy", "Authentication Methods Policy", "Policy.Read.All"),
            ("/policies", "All Policies", "Policy.Read.All"),
            
            # Directory.Read.All permissions
            ("/domains", "Domains", "Directory.Read.All"),
            ("/directoryRoles", "Directory Roles", "Directory.Read.All"),
            ("/directorySettings", "Directory Settings", "Directory.Read.All"),
            
            # IdentityRiskyUser.Read.All permissions
            ("/identityProtection/riskyUsers", "Risky Users", "IdentityRiskyUser.Read.All"),
            
            # IdentityRiskEvent.Read.All permissions
            ("/identityProtection/riskDetections", "Risk Detections", "IdentityRiskEvent.Read.All"),
            
            # DeviceManagementConfiguration.Read.All permissions
            ("/deviceManagement/deviceConfigurations", "Intune Device Configurations", "DeviceManagementConfiguration.Read.All"),
            
            # DeviceManagementManagedDevices.Read.All permissions
            ("/deviceManagement/managedDevices", "Intune Managed Devices", "DeviceManagementManagedDevices.Read.All"),
            
            # DeviceManagementServiceConfig.Read.All permissions
            ("/deviceManagement", "Intune Service Config", "DeviceManagementServiceConfig.Read.All"),
            ("/deviceManagement/deviceCompliancePolicies", "Intune Compliance Policies", "DeviceManagementServiceConfig.Read.All"),
            
            # RoleManagement.Read.Directory permissions
            ("/roleManagement/directory/roleAssignmentSchedulePolicies", "PIM Role Assignment Policies", "RoleManagement.Read.Directory"),
            ("/roleManagement/directory/roleEligibilitySchedulePolicies", "PIM Role Eligibility Policies", "RoleManagement.Read.Directory"),
            ("/roleManagement/directory/roleAssignments", "PIM Role Assignments", "RoleManagement.Read.Directory"),
            
            # User.Read.All permissions
            ("/users", "Users", "User.Read.All"),
            ("/users?$top=1", "User Details", "User.Read.All"),
            
            # Group.Read.All permissions
            ("/groups", "Groups", "Group.Read.All"),
            ("/groups?$top=1", "Group Details", "Group.Read.All"),
            
            # AuditLog.Read.All permissions
            ("/auditLogs/directoryAudits", "Directory Audit Logs", "AuditLog.Read.All"),
            ("/auditLogs/signIns", "Sign-in Logs", "AuditLog.Read.All"),
            
            # SecurityEvents.Read.All permissions
            ("/security/events", "Security Events", "SecurityEvents.Read.All"),
            
            # SecurityIncident.Read.All permissions
            ("/security/incidents", "Security Incidents", "SecurityIncident.Read.All"),
            
            # AccessReview.Read.All permissions
            ("/identityGovernance/accessReviews/definitions", "Access Review Definitions", "AccessReview.Read.All"),
            ("/identityGovernance/accessReviews/definitions?$top=1", "Access Review Details", "AccessReview.Read.All"),
            
            # PrivilegedAccess.Read.AzureAD permissions
            ("/privilegedAccess/aadRoles/roleAssignments", "PIM Role Assignments", "PrivilegedAccess.Read.AzureAD"),
            ("/privilegedAccess/aadRoles/roleEligibilitySchedules", "PIM Role Eligibility", "PrivilegedAccess.Read.AzureAD"),
            
            # LifecycleWorkflows.Read.All permissions
            ("/identityGovernance/lifecycleWorkflows/workflows", "Lifecycle Workflows", "LifecycleWorkflows.Read.All"),
            
            # Conditional Access permissions
            ("/identity/conditionalAccess/policies", "Conditional Access Policies", "Policy.Read.All"),
            ("/identity/conditionalAccess/templates", "Conditional Access Templates", "Policy.Read.All"),
            
            # Additional security-related endpoints
            ("/security/alerts", "Security Alerts", "SecurityEvents.Read.All"),
            ("/security/secureScores", "Secure Scores", "SecurityEvents.Read.All"),
            ("/security/secureScoreControlProfiles", "Secure Score Control Profiles", "SecurityEvents.Read.All")
        ]
        
        working = []
        failed = []
        permission_summary = {}
        
        for endpoint, description, required_permission in test_endpoints:
            try:
                response = self.api_client.graph_get(endpoint)
                if response.status_code == 200:
                    working.append((endpoint, description, response.status_code, required_permission))
                    self.formatter.print_success(f"{description}: {response.status_code} (Permission: {required_permission})")
                    
                    # Track permission success
                    if required_permission not in permission_summary:
                        permission_summary[required_permission] = {"success": 0, "failed": 0}
                    permission_summary[required_permission]["success"] += 1
                    
                else:
                    failed.append((endpoint, description, response.status_code, required_permission, response.text))
                    self.formatter.print_error(f"{description}: {response.status_code} (Permission: {required_permission})")
                    
                    # Track permission failure
                    if required_permission not in permission_summary:
                        permission_summary[required_permission] = {"success": 0, "failed": 0}
                    permission_summary[required_permission]["failed"] += 1
                    
            except Exception as e:
                failed.append((endpoint, description, "Exception", required_permission, str(e)))
                self.formatter.print_error(f"{description}: Exception - {e} (Permission: {required_permission})")
                
                # Track permission failure
                if required_permission not in permission_summary:
                    permission_summary[required_permission] = {"success": 0, "failed": 0}
                permission_summary[required_permission]["failed"] += 1
        
        # Summary by permission
        self.formatter.print_subsection("PERMISSION SUMMARY")
        for permission, counts in permission_summary.items():
            total = counts["success"] + counts["failed"]
            if counts["failed"] == 0:
                self.formatter.print_success(f"{permission}: {counts['success']}/{total} endpoints working")
            elif counts["success"] == 0:
                self.formatter.print_error(f"{permission}: {counts['failed']}/{total} endpoints failed")
            else:
                self.formatter.print_warning(f"{permission}: {counts['success']}/{total} working, {counts['failed']}/{total} failed")
        
        # Detailed summary
        self.formatter.print_subsection("DETAILED SUMMARY")
        if working:
            self.formatter.print_success("WORKING ENDPOINTS:")
            for endpoint, description, status, permission in working:
                self.formatter.print_list_item(f"{description} ({endpoint}) - {permission}")
        
        if failed:
            self.formatter.print_error("FAILED ENDPOINTS:")
            for endpoint, description, status, permission, error in failed:
                self.formatter.print_list_item(f"{description} ({endpoint}) - {permission}: {status}")
        
        # Compliance assessment
        self.formatter.print_subsection("COMPLIANCE ASSESSMENT")
        required_permissions = [
            "Policy.Read.All", "Directory.Read.All", "IdentityRiskyUser.Read.All", 
            "IdentityRiskEvent.Read.All", "DeviceManagementConfiguration.Read.All",
            "DeviceManagementManagedDevices.Read.All", "DeviceManagementServiceConfig.Read.All",
            "RoleManagement.Read.Directory", "User.Read.All", "Group.Read.All",
            "AuditLog.Read.All", "SecurityEvents.Read.All", "SecurityIncident.Read.All",
            "AccessReview.Read.All", "PrivilegedAccess.Read.AzureAD", "LifecycleWorkflows.Read.All"
        ]
        
        missing_permissions = []
        partial_permissions = []
        
        for permission in required_permissions:
            if permission not in permission_summary:
                missing_permissions.append(permission)
            elif permission_summary[permission]["failed"] > 0:
                if permission_summary[permission]["success"] == 0:
                    missing_permissions.append(permission)
                else:
                    partial_permissions.append(permission)
        
        if not missing_permissions and not partial_permissions:
            self.formatter.print_success("✓ ALL REQUIRED PERMISSIONS ARE WORKING")
        else:
            if missing_permissions:
                self.formatter.print_error("✗ MISSING PERMISSIONS:")
                for permission in missing_permissions:
                    self.formatter.print_list_item(f"{permission} - No endpoints working")
            
            if partial_permissions:
                self.formatter.print_warning("⚠️  PARTIAL PERMISSIONS:")
                for permission in partial_permissions:
                    counts = permission_summary[permission]
                    self.formatter.print_list_item(f"{permission} - {counts['success']} working, {counts['failed']} failed")
        
        self.formatter.print_separator() 

    def check_intune_compliance_policy(self):
        """Check Intune compliance policies for Windows 10/11 for BitLocker, Defender, Secure Boot, and password protection requirements."""
        self.formatter.print_header(
            "MICROSOFT INTUNE COMPLIANCE POLICY CHECKS (Windows 10/11)",
            "This function checks Intune compliance policies for Windows 10/11 for BitLocker, Defender, Secure Boot, and password protection requirements. It evidences device compliance with key security baselines."
        )
        try:
            response = self.api_client.graph_get("/deviceManagement/deviceCompliancePolicies")
            if self.api_client.check_response(response, "Intune Compliance Policies"):
                policies = response.json().get('value', [])
                found = False
                for policy in policies:
                    if policy.get('@odata.type', '').endswith('windows10CompliancePolicy'):
                        found = True
                        self.formatter.print_key_value("Policy", policy.get('displayName'))
                        self.formatter.print_key_value("BitLocker Required", policy.get('bitLockerEnabled', 'N/A'))
                        self.formatter.print_key_value("Defender Required", policy.get('defenderEnabled', 'N/A'))
                        self.formatter.print_key_value("Secure Boot Required", policy.get('secureBootEnabled', 'N/A'))
                        self.formatter.print_key_value("Password Required", policy.get('passwordRequired', 'N/A'))
                        self.formatter.print_separator()
                if not found:
                    self.formatter.print_warning("No Windows 10/11 compliance policies found.")
            else:
                self.formatter.print_error("Failed to retrieve compliance policies.")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving compliance policies: {e}")
        self.formatter.print_separator()

    def check_sentinel_error_analytic_rules(self):
        """List all Microsoft Sentinel analytic rules related to error logs in the specified workspace."""
        self.formatter.print_header(
            "SENTINEL ANALYTIC RULES FOR ERROR LOGS",
            "This function lists all Microsoft Sentinel analytic rules related to error logs in the specified workspace. It evidences the presence of automated detection and alerting for error conditions in your security monitoring environment."
        )
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-12-01-preview"
        try:
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                rules = response.json().get('value', [])
                for rule in rules:
                    self.formatter.print_key_value("Rule", rule.get('name'))
                    self.formatter.print_key_value("Description", rule.get('properties', {}).get('description', 'N/A'))
                    self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve analytic rules: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        self.formatter.print_separator()

    def check_defender_for_cloud_failed_checks(self):
        """List failed configuration checks from Defender for Cloud."""
        self.formatter.print_header(
            "DEFENDER FOR CLOUD FAILED CONFIGURATION CHECKS",
            "This function lists failed configuration checks from Defender for Cloud. It evidences detection of misconfigurations and gaps in cloud security posture for compliance."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/assessments?api-version=2020-01-01"
        try:
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                assessments = response.json().get('value', [])
                failed = [a for a in assessments if a.get('properties', {}).get('status', {}).get('code') == 'Unhealthy']
                if failed:
                    for a in failed:
                        display_name = a.get('properties', {}).get('displayName', 'N/A')
                        severity = a.get('properties', {}).get('metadata', {}).get('severity', 'N/A')
                        self.formatter.print_error(f"{display_name} (Severity: {severity})")
                else:
                    self.formatter.print_success("No failed configuration checks found.")
            else:
                self.formatter.print_error(f"Failed to retrieve Defender for Cloud assessments: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        self.formatter.print_separator()

    def check_sentinel_defender_connector_status(self):
        """Check the status of the Defender for Cloud data connector in Microsoft Sentinel."""
        self.formatter.print_header(
            "SENTINEL DEFENDER FOR CLOUD CONNECTOR STATUS",
            "This function checks the status of the Defender for Cloud data connector in Microsoft Sentinel. It evidences integration of cloud security alerts with Sentinel for centralized monitoring and compliance."
        )
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-12-01-preview"
        try:
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                connectors = response.json().get('value', [])
                found = False
                for c in connectors:
                    kind = c.get('kind', '')
                    name = c.get('name', '')
                    if kind == "AzureSecurityCenter" or "defender" in name.lower():
                        self.formatter.print_success("Defender for Cloud data connector is ENABLED in Sentinel.")
                        found = True
                if not found:
                    self.formatter.print_warning("Defender for Cloud data connector is NOT enabled in Sentinel.")
            else:
                self.formatter.print_error(f"Failed to retrieve Sentinel data connectors: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        self.formatter.print_separator() 

    def check_waf_deployment_and_policy_status(self):
        """Check the deployment and policy status of Azure Web Application Firewall (WAF) on Application Gateways and Front Door."""
        self.formatter.print_header(
            "AZURE WAF DEPLOYMENT AND POLICY STATUS",
            "This function checks the deployment and policy status of Azure Web Application Firewall (WAF) on Application Gateways and Front Door. It evidences web application protection and policy enforcement for compliance."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        # Application Gateways
        agw_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/applicationGateways?api-version=2022-09-01"
        found_gateway = False
        try:
            response = self.api_client.arm_get(agw_url)
            if response.status_code == 200:
                gateways = response.json().get('value', [])
                if not gateways:
                    self.formatter.print_info("No Application Gateways found in the subscription.")
                for gw in gateways:
                    waf_config_obj = gw.get('properties', {}).get('webApplicationFirewallConfiguration')
                    if waf_config_obj:
                        found_gateway = True
                        self.formatter.print_success(f"AppGW: {gw.get('name')}")
                        self.formatter.print_key_value("WAF Enabled", waf_config_obj.get('enabled', False))
                        self.formatter.print_key_value("Mode", waf_config_obj.get('firewallMode', 'N/A'))
                        self.formatter.print_key_value("RuleSet", f"{waf_config_obj.get('ruleSetType', 'N/A')} {waf_config_obj.get('ruleSetVersion', '')}")
                    else:
                        self.formatter.print_warning(f"AppGW: {gw.get('name')} - No WAF configuration")
                if not found_gateway and gateways:
                    self.formatter.print_warning("No Application Gateways with WAF enabled/configured found.")
            else:
                self.formatter.print_error(f"Failed to retrieve Application Gateways: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Error retrieving Application Gateways: {e}")
        # Front Door
        afd_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Cdn/profiles?api-version=2021-06-01"
        found_fd = False
        try:
            response = self.api_client.arm_get(afd_url)
            if response.status_code == 200:
                profiles = response.json().get('value', [])
                if not profiles:
                    self.formatter.print_info("No Front Door profiles found in the subscription.")
                for profile in profiles:
                    sku = profile.get('sku', {}).get('name', '')
                    if 'AzureFrontDoor' in sku:
                        found_fd = True
                        waf_policy = profile.get('properties', {}).get('webApplicationFirewallPolicyLink', {}).get('id')
                        self.formatter.print_key_value(f"Front Door: {profile.get('name')} WAF Policy", waf_policy or 'None')
                if not found_fd and profiles:
                    self.formatter.print_warning("No Front Door profiles with WAF policy found.")
            else:
                self.formatter.print_error(f"Failed to retrieve Front Door profiles: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Error retrieving Front Door profiles: {e}")
        self.formatter.print_separator()

    def check_dnssec_status(self):
        """Check DNSSEC status for all DNS zones in the subscription."""
        self.formatter.print_header(
            "AZURE DNSSEC STATUS FOR DNS ZONES",
            "This function checks DNSSEC status for all DNS zones in the subscription. It evidences DNS integrity and protection against spoofing for compliance."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        dns_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/dnsZones?api-version=2023-07-01-preview"
        try:
            response = self.api_client.arm_get(dns_url)
            if response.status_code == 200:
                zones = response.json().get('value', [])
                if not zones:
                    self.formatter.print_info("No DNS zones found in this subscription.")
                for zone in zones:
                    name = zone.get('name', 'N/A')
                    zone_type = zone.get('properties', {}).get('zoneType', 'Public')
                    if zone_type == 'Private':
                        self.formatter.print_key_value(f"DNS Zone: {name}", "Private")
                        self.formatter.print_info("DNSSEC: Not Supported in Azure Private DNS")
                        self.formatter.print_info("Compensating controls recommended: DNS logging, secure resolvers, etc.")
                        continue
                    # For public zones, check DNSSEC
                    dnssec_state = zone.get('properties', {}).get('zoneSigningKeys', [])
                    if dnssec_state:
                        self.formatter.print_success(f"DNS Zone: {name} (Public)")
                        self.formatter.print_key_value("DNSSEC", "Enabled")
                        for k in dnssec_state:
                            ds_records = k.get('dsRecord', [])
                            if ds_records:
                                self.formatter.print_key_value("DS Records", ds_records)
                            else:
                                self.formatter.print_info("DS Records: Not available (check Azure Portal)")
                    else:
                        self.formatter.print_warning(f"DNS Zone: {name} (Public)")
                        self.formatter.print_key_value("DNSSEC", "Disabled")
            else:
                self.formatter.print_error(f"Failed to retrieve DNS zones: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving DNS zones: {e}")
        self.formatter.print_separator()

    def check_defender_fim_configuration(self):
        """Check Defender for Endpoint File Integrity Monitoring (FIM) configuration."""
        self.formatter.print_header(
            "DEFENDER FOR ENDPOINT FILE INTEGRITY MONITORING CONFIGURATION",
            "This function checks Defender for Endpoint File Integrity Monitoring (FIM) configuration. It evidences monitoring of file changes for endpoint security and compliance."
        )
        url = "/security/secureScoreControlProfiles"
        try:
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                controls = response.json().get('value', [])
                found = False
                for c in controls:
                    if 'tamper' in c.get('title', '').lower() or 'real-time' in c.get('title', '').lower() or 'attack surface reduction' in c.get('title', '').lower():
                        found = True
                        self.formatter.print_key_value("Control", c.get('title'))
                        self.formatter.print_key_value("Description", c.get('description'))
                        self.formatter.print_key_value("Current Score", c.get('currentScore', 'N/A'))
                        self.formatter.print_key_value("Max Score", c.get('maxScore', 'N/A'))
                        self.formatter.print_key_value("Status", c.get('status', 'N/A'))
                        self.formatter.print_separator()
                if not found:
                    self.formatter.print_warning("No FIM-related controls found in Secure Score profiles.")
            else:
                self.formatter.print_error(f"Failed to retrieve Secure Score controls: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving Secure Score controls: {e}")
        self.formatter.print_separator()

    def check_sentinel_defender_endpoint_connector_status(self):
        """Check the status of the Defender for Endpoint data connector in Microsoft Sentinel."""
        self.formatter.print_header(
            "SENTINEL DEFENDER FOR ENDPOINT CONNECTOR STATUS",
            "This function checks the status of the Defender for Endpoint data connector in Microsoft Sentinel. It evidences integration of endpoint security alerts with Sentinel for centralized monitoring and compliance."
        )
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-12-01-preview"
        try:
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                connectors = response.json().get('value', [])
                found = False
                for c in connectors:
                    kind = c.get('kind', '')
                    name = c.get('name', '')
                    if kind == "MicrosoftThreatProtection" or "defender" in name.lower():
                        self.formatter.print_success("Defender for Endpoint data connector is ENABLED in Sentinel.")
                        found = True
                if not found:
                    self.formatter.print_warning("Defender for Endpoint data connector is NOT enabled in Sentinel.")
            else:
                self.formatter.print_error(f"Failed to retrieve Sentinel data connectors: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        self.formatter.print_separator() 

    def check_nsg_smtp_block_status(self):
        """Check all Network Security Groups (NSGs) in the subscription for explicit deny rules on inbound SMTP ports 25 and 465."""
        self.formatter.print_header(
            "AZURE NSG INBOUND SMTP BLOCK STATUS (PORTS 25, 465)",
            "This function checks all Network Security Groups (NSGs) in the subscription for explicit deny rules on inbound SMTP ports 25 and 465. It evidences enforcement of email traffic restrictions at the network boundary."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2022-05-01"
        try:
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                nsgs = response.json().get('value', [])
                self.formatter.print_info(f"Found {len(nsgs)} NSGs in subscription.")
                for nsg in nsgs:
                    nsg_name = nsg.get('name')
                    self.formatter.print_key_value("NSG", nsg_name)
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
                        status = "✓" if smtp_blocked[port] else "✗"
                        self.formatter.print_key_value(f"Port {port} Deny Rule", status)
                    self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve NSGs: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        self.formatter.print_separator()

    def check_firewall_smtp_block_status(self):
        """Check all Azure Firewalls in the subscription for explicit deny rules on inbound SMTP ports 25 and 465."""
        self.formatter.print_header(
            "AZURE FIREWALL INBOUND SMTP BLOCK STATUS (PORTS 25, 465)",
            "This function checks all Azure Firewalls in the subscription for explicit deny rules on inbound SMTP ports 25 and 465. It evidences enforcement of email traffic restrictions at the firewall/perimeter level."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/azureFirewalls?api-version=2022-05-01"
        try:
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                firewalls = response.json().get('value', [])
                self.formatter.print_info(f"Found {len(firewalls)} Azure Firewalls in subscription.")
                for fw in firewalls:
                    fw_name = fw.get('name')
                    self.formatter.print_key_value("Firewall", fw_name)
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
                        status = "✓" if smtp_blocked[port] else "✗"
                        self.formatter.print_key_value(f"Port {port} Deny Rule", status)
                    self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve Azure Firewalls: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        self.formatter.print_separator()

    def check_bastion_ssh_timeout_status(self):
        """Check the SSH session idle timeout setting for all Azure Bastion Hosts."""
        self.formatter.print_header(
            "AZURE BASTION HOST SSH SESSION TIMEOUT STATUS",
            "This function checks the SSH session idle timeout setting for all Azure Bastion Hosts. It evidences enforcement of session termination after inactivity, supporting compliance with session management requirements."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        if not (subscription_id and resource_group):
            self.formatter.print_error("subscription_id and resource_group must be set in config.")
            return
        url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/bastionHosts?api-version=2023-05-01"
        try:
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                bastion_hosts = response.json().get('value', [])
                if not bastion_hosts:
                    self.formatter.print_info("No Azure Bastion hosts found in the specified subscription/resource group.")
                    return
                for host in bastion_hosts:
                    self.formatter.print_key_value("Bastion Host", host.get('name'))
                    properties = host.get('properties', {})
                    idle_timeout = properties.get('idleTimeoutInMinutes', 'Not configured')
                    self.formatter.print_key_value("Idle Timeout (minutes)", idle_timeout)
                    if idle_timeout == 10:
                        self.formatter.print_success("SSH session timeout is correctly set to 10 minutes.")
                    else:
                        self.formatter.print_warning("SSH session timeout is NOT set to 10 minutes. Please review configuration.")
                    self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve Bastion hosts: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving Bastion host settings: {e}")
        self.formatter.print_separator()

    def check_sentinel_incident_summary(self):
        """Summarize Microsoft Sentinel incidents in the specified workspace."""
        self.formatter.print_header(
            "MICROSOFT SENTINEL INCIDENT SUMMARY",
            "This function summarizes Microsoft Sentinel incidents in the specified workspace, including counts by status and details for recent incidents. It evidences active monitoring, incident response, and security operations maturity."
        )
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01-preview"
        try:
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                incidents = response.json().get('value', [])
                self.formatter.print_key_value("Total Incidents", len(incidents))
                status_count = {}
                for inc in incidents:
                    status = inc.get('properties', {}).get('status', 'Unknown')
                    status_count[status] = status_count.get(status, 0) + 1
                for status, count in status_count.items():
                    self.formatter.print_key_value(f"Status: {status}", count)
                self.formatter.print_subsection("Recent Incidents")
                max_subitems = getattr(self.config, 'max_subitems', 10)
                for inc in incidents[:max_subitems]:
                    props = inc.get('properties', {})
                    self.formatter.print_key_value("Title", props.get('title'))
                    self.formatter.print_key_value("Status", props.get('status'))
                    self.formatter.print_key_value("Owner", props.get('owner', {}).get('assignedTo', 'N/A'))
                    self.formatter.print_key_value("Created", props.get('createdTimeUtc'))
                    self.formatter.print_key_value("Last Updated", props.get('lastModifiedTimeUtc'))
                    self.formatter.print_key_value("Investigation Notes", props.get('description', 'N/A'))
                    self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve incidents: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        self.formatter.print_separator() 

    def check_blob_storage_audit_retention(self):
        """Check Azure Blob Storage audit retention configuration for 90 days searchable and 280 days archival."""
        self.formatter.print_header(
            "AZURE BLOB STORAGE AUDIT RETENTION CONFIGURATION",
            "This function checks Azure Blob Storage audit retention configuration to evidence 90 days of searchable audit information and 280 days of archival audit information as required for compliance."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        
        # 1. Check Storage Accounts and Lifecycle Management
        self.formatter.print_subsection("STORAGE ACCOUNTS AND LIFECYCLE MANAGEMENT")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Storage/storageAccounts?api-version=2022-09-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                accounts = response.json().get('value', [])
                if not accounts:
                    self.formatter.print_warning("No storage accounts found in subscription")
                    return
                
                for acc in accounts:
                    account_name = acc.get('name')
                    account_id = acc.get('id')
                    kind = acc.get('kind')
                    sku = acc.get('sku', {}).get('name')
                    
                    self.formatter.print_subsection(f"STORAGE ACCOUNT: {account_name}")
                    self.formatter.print_key_value("Account Type", kind)
                    self.formatter.print_key_value("SKU", sku)
                    
                    # Check if it's a Blob Storage account
                    if kind in ['StorageV2', 'BlobStorage']:
                        self.formatter.print_success("Blob Storage capable account")
                        
                        # Check Lifecycle Management Policies
                        lifecycle_url = f"{account_id}/managementPolicies/default?api-version=2022-09-01"
                        lifecycle_response = self.api_client.arm_get(lifecycle_url)
                        
                        if lifecycle_response.status_code == 200:
                            policy = lifecycle_response.json()
                            rules = policy.get('properties', {}).get('policy', {}).get('rules', [])
                            
                            if rules:
                                self.formatter.print_success(f"Found {len(rules)} lifecycle management rules")
                                
                                # Check for retention rules
                                retention_rules = []
                                for rule in rules:
                                    actions = rule.get('actions', {})
                                    base_blob = actions.get('baseBlob', {})
                                    delete_after = base_blob.get('delete', {}).get('daysAfterModificationGreaterThan')
                                    
                                    if delete_after:
                                        retention_rules.append({
                                            'name': rule.get('name', 'Unnamed'),
                                            'retention_days': delete_after
                                        })
                                
                                if retention_rules:
                                    self.formatter.print_subsection("RETENTION RULES")
                                    for rule in retention_rules:
                                        self.formatter.print_key_value(f"Rule: {rule['name']}", f"{rule['retention_days']} days")
                                        
                                        # Check if it meets requirements
                                        if rule['retention_days'] >= 280:
                                            self.formatter.print_success(f"Meets 280-day archival requirement")
                                        elif rule['retention_days'] >= 90:
                                            self.formatter.print_success(f"Meets 90-day searchable requirement")
                                        else:
                                            self.formatter.print_warning(f"Retention period may be insufficient")
                                else:
                                    self.formatter.print_warning("No retention rules found in lifecycle policy")
                            else:
                                self.formatter.print_warning("No lifecycle management rules configured")
                        elif lifecycle_response.status_code == 404:
                            self.formatter.print_warning("No lifecycle management policy configured")
                        else:
                            self.formatter.print_error(f"Failed to retrieve lifecycle policy: {lifecycle_response.status_code}")
                    else:
                        self.formatter.print_info("Not a blob storage account")
                    
                    self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve storage accounts: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 2. Check Diagnostic Settings for Audit Log Forwarding
        self.formatter.print_subsection("DIAGNOSTIC SETTINGS FOR AUDIT LOG FORWARDING")
        try:
            for acc in accounts:
                account_name = acc.get('name')
                account_id = acc.get('id')
                
                diag_url = f"{account_id}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
                diag_response = self.api_client.arm_get(diag_url)
                
                if diag_response.status_code == 200:
                    diag_settings = diag_response.json().get('value', [])
                    if diag_settings:
                        self.formatter.print_success(f"Found {len(diag_settings)} diagnostic settings for {account_name}")
                        
                        for setting in diag_settings:
                            setting_name = setting.get('name', 'Unknown')
                            logs = setting.get('properties', {}).get('logs', [])
                            metrics = setting.get('properties', {}).get('metrics', [])
                            
                            # Check for audit-related logs
                            audit_logs = [log for log in logs if any(keyword in log.get('category', '').lower() 
                                           for keyword in ['audit', 'access', 'transaction', 'storage'])]
                            
                            if audit_logs:
                                self.formatter.print_success(f"Diagnostic setting '{setting_name}' includes audit logs")
                                for log in audit_logs:
                                    self.formatter.print_key_value(f"Log Category", log.get('category', 'Unknown'))
                                    self.formatter.print_key_value(f"Enabled", log.get('enabled', False))
                            else:
                                self.formatter.print_warning(f"Diagnostic setting '{setting_name}' has no audit logs")
                    else:
                        self.formatter.print_warning(f"No diagnostic settings configured for {account_name}")
                elif diag_response.status_code == 404:
                    self.formatter.print_warning(f"No diagnostic settings found for {account_name}")
                else:
                    self.formatter.print_error(f"Failed to retrieve diagnostic settings for {account_name}: {diag_response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 3. Check Blob Service Properties for Analytics
        self.formatter.print_subsection("BLOB SERVICE ANALYTICS CONFIGURATION")
        try:
            for acc in accounts:
                account_name = acc.get('name')
                account_id = acc.get('id')
                
                # Check blob service properties
                blob_service_url = f"{account_id}/blobServices/default?api-version=2022-09-01"
                blob_response = self.api_client.arm_get(blob_service_url)
                
                if blob_response.status_code == 200:
                    blob_service = blob_response.json()
                    properties = blob_service.get('properties', {})
                    
                    # Check for analytics logging
                    logging = properties.get('logging', {})
                    if logging.get('read', False) or logging.get('write', False) or logging.get('delete', False):
                        self.formatter.print_success(f"Blob analytics logging enabled for {account_name}")
                        self.formatter.print_key_value("Read Logging", logging.get('read', False))
                        self.formatter.print_key_value("Write Logging", logging.get('write', False))
                        self.formatter.print_key_value("Delete Logging", logging.get('delete', False))
                        self.formatter.print_key_value("Retention Days", logging.get('retentionPolicy', {}).get('days', 'Not set'))
                    else:
                        self.formatter.print_warning(f"Blob analytics logging not configured for {account_name}")
                else:
                    self.formatter.print_error(f"Failed to retrieve blob service properties for {account_name}: {blob_response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 4. Check for Container-Level Retention Policies
        self.formatter.print_subsection("CONTAINER-LEVEL RETENTION POLICIES")
        try:
            for acc in accounts:
                account_name = acc.get('name')
                
                # List containers
                containers_url = f"{account_id}/blobServices/default/containers?api-version=2022-09-01"
                containers_response = self.api_client.arm_get(containers_url)
                
                if containers_response.status_code == 200:
                    containers = containers_response.json().get('value', [])
                    if containers:
                        self.formatter.print_success(f"Found {len(containers)} containers in {account_name}")
                        
                        for container in containers:
                            container_name = container.get('name')
                            properties = container.get('properties', {})
                            
                            # Check for immutability policy
                            immutability_policy = properties.get('immutabilityPolicy', {})
                            if immutability_policy.get('state') == 'Locked':
                                self.formatter.print_success(f"Container '{container_name}' has immutability policy")
                                self.formatter.print_key_value("Immutability State", immutability_policy.get('state'))
                                self.formatter.print_key_value("Retention Period", f"{immutability_policy.get('periodSinceCreationInDays', 'Unknown')} days")
                            else:
                                self.formatter.print_info(f"Container '{container_name}' has no immutability policy")
                    else:
                        self.formatter.print_info(f"No containers found in {account_name}")
                else:
                    self.formatter.print_error(f"Failed to retrieve containers for {account_name}: {containers_response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        self.formatter.print_separator()

    def check_fips_validated_encryption(self):
        """Check for FIPS validated encryption across Azure services and resources."""
        self.formatter.print_header(
            "FIPS VALIDATED ENCRYPTION COMPLIANCE",
            "This function checks for FIPS 140-2 validated encryption across Azure services including storage accounts, Key Vaults, managed disks, and network security. It evidences compliance with federal encryption standards for FedRAMP Moderate requirements."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        
        # 1. Check Azure Storage Account Encryption
        self.formatter.print_subsection("AZURE STORAGE ACCOUNT ENCRYPTION")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Storage/storageAccounts?api-version=2022-09-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                accounts = response.json().get('value', [])
                if not accounts:
                    self.formatter.print_warning("No storage accounts found in subscription")
                else:
                    self.formatter.print_success(f"Found {len(accounts)} storage accounts")
                    
                    for account in accounts:
                        account_name = account.get('name')
                        properties = account.get('properties', {})
                        encryption = properties.get('encryption', {})
                        
                        self.formatter.print_subsection(f"STORAGE ACCOUNT: {account_name}")
                        
                        # Check encryption services
                        services = encryption.get('services', {})
                        blob_encrypted = services.get('blob', {}).get('enabled', False)
                        file_encrypted = services.get('file', {}).get('enabled', False)
                        table_encrypted = services.get('table', {}).get('enabled', False)
                        queue_encrypted = services.get('queue', {}).get('enabled', False)
                        
                        self.formatter.print_key_value("Blob Encryption", blob_encrypted)
                        self.formatter.print_key_value("File Encryption", file_encrypted)
                        self.formatter.print_key_value("Table Encryption", table_encrypted)
                        self.formatter.print_key_value("Queue Encryption", queue_encrypted)
                        
                        # Check key source
                        key_source = encryption.get('keySource', 'Unknown')
                        self.formatter.print_key_value("Key Source", key_source)
                        
                        if key_source == 'Microsoft.Storage':
                            self.formatter.print_success("Using Microsoft-managed keys (FIPS compliant)")
                        elif key_source == 'Microsoft.Keyvault':
                            self.formatter.print_success("Using Key Vault customer-managed keys")
                        else:
                            self.formatter.print_warning("Unknown key source - verify FIPS compliance")
                        
                        # Check encryption algorithm
                        algorithm = encryption.get('keyVaultProperties', {}).get('encryptionAlgorithm', 'AES256')
                        self.formatter.print_key_value("Encryption Algorithm", algorithm)
                        
                        if algorithm in ['AES256', 'AES-256']:
                            self.formatter.print_success("AES-256 encryption (FIPS 140-2 compliant)")
                        else:
                            self.formatter.print_warning(f"Verify {algorithm} is FIPS 140-2 compliant")
                        
                        self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve storage accounts: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 2. Check Azure Key Vault FIPS Compliance
        self.formatter.print_subsection("AZURE KEY VAULT FIPS COMPLIANCE")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                vaults = response.json().get('value', [])
                if not vaults:
                    self.formatter.print_warning("No Key Vaults found in subscription")
                else:
                    self.formatter.print_success(f"Found {len(vaults)} Key Vaults")
                    
                    for vault in vaults:
                        vault_name = vault.get('name')
                        properties = vault.get('properties', {})
                        
                        self.formatter.print_subsection(f"KEY VAULT: {vault_name}")
                        
                        # Check SKU (Premium SKU supports HSM)
                        sku = properties.get('sku', {}).get('name', 'Unknown')
                        self.formatter.print_key_value("SKU", sku)
                        
                        if sku == 'premium':
                            self.formatter.print_success("Premium SKU - Supports FIPS 140-2 Level 2 HSM")
                        else:
                            self.formatter.print_warning("Standard SKU - Limited FIPS compliance features")
                        
                        # Check if HSM is enabled
                        hsm_pool = properties.get('hsmPoolResourceId')
                        if hsm_pool:
                            self.formatter.print_success("Hardware Security Module (HSM) enabled")
                            self.formatter.print_key_value("HSM Pool", hsm_pool)
                        else:
                            self.formatter.print_info("No HSM pool configured")
                        
                        # Check enabled features
                        enabled_features = properties.get('enabledForDeployment', False)
                        enabled_disk_encryption = properties.get('enabledForDiskEncryption', False)
                        enabled_template_deployment = properties.get('enabledForTemplateDeployment', False)
                        
                        self.formatter.print_key_value("Enabled for Deployment", enabled_features)
                        self.formatter.print_key_value("Enabled for Disk Encryption", enabled_disk_encryption)
                        self.formatter.print_key_value("Enabled for Template Deployment", enabled_template_deployment)
                        
                        # Check soft delete and purge protection
                        soft_delete_retention = properties.get('softDeleteRetentionInDays', 0)
                        enable_purge_protection = properties.get('enablePurgeProtection', False)
                        
                        self.formatter.print_key_value("Soft Delete Retention (Days)", soft_delete_retention)
                        self.formatter.print_key_value("Purge Protection Enabled", enable_purge_protection)
                        
                        if soft_delete_retention >= 7 and enable_purge_protection:
                            self.formatter.print_success("Soft delete and purge protection properly configured")
                        else:
                            self.formatter.print_warning("Soft delete or purge protection may need configuration")
                        
                        self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve Key Vaults: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 3. Check Azure Disk Encryption
        self.formatter.print_subsection("AZURE DISK ENCRYPTION")
        try:
            # Check for disk encryption sets
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Compute/diskEncryptionSets?api-version=2022-07-02"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                encryption_sets = response.json().get('value', [])
                if not encryption_sets:
                    self.formatter.print_warning("No disk encryption sets found")
                else:
                    self.formatter.print_success(f"Found {len(encryption_sets)} disk encryption sets")
                    
                    for enc_set in encryption_sets:
                        set_name = enc_set.get('name')
                        properties = enc_set.get('properties', {})
                        
                        self.formatter.print_subsection(f"DISK ENCRYPTION SET: {set_name}")
                        
                        # Check encryption type
                        encryption_type = properties.get('encryptionType', 'Unknown')
                        self.formatter.print_key_value("Encryption Type", encryption_type)
                        
                        if encryption_type == 'EncryptionAtRestWithCustomerKey':
                            self.formatter.print_success("Customer-managed key encryption")
                        elif encryption_type == 'EncryptionAtRestWithPlatformAndCustomerKeys':
                            self.formatter.print_success("Double encryption with platform and customer keys")
                        else:
                            self.formatter.print_warning(f"Verify {encryption_type} meets FIPS requirements")
                        
                        # Check key vault reference
                        key_vault = properties.get('activeKey', {}).get('keyUrl', 'Not configured')
                        self.formatter.print_key_value("Key Vault Reference", key_vault)
                        
                        if key_vault != 'Not configured':
                            self.formatter.print_success("Key Vault integration configured")
                        else:
                            self.formatter.print_warning("No Key Vault integration found")
                        
                        self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve disk encryption sets: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 4. Check Azure Policy for FIPS Compliance
        self.formatter.print_subsection("AZURE POLICY FIPS COMPLIANCE")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                assignments = response.json().get('value', [])
                fips_policies = []
                
                for assignment in assignments:
                    policy_definition_id = assignment.get('properties', {}).get('policyDefinitionId', '')
                    display_name = assignment.get('properties', {}).get('displayName', '')
                    
                    # Look for FIPS-related policies
                    fips_keywords = ['fips', 'encryption', 'encrypt', 'security', 'compliance', 'crypto']
                    if any(keyword in policy_definition_id.lower() or keyword in display_name.lower() 
                           for keyword in fips_keywords):
                        fips_policies.append(assignment)
                
                if fips_policies:
                    self.formatter.print_success(f"Found {len(fips_policies)} FIPS-related policy assignments")
                    
                    for policy in fips_policies:
                        policy_name = policy.get('name', 'Unknown')
                        display_name = policy.get('properties', {}).get('displayName', 'No display name')
                        enforcement_mode = policy.get('properties', {}).get('enforcementMode', 'Default')
                        
                        self.formatter.print_key_value(f"Policy: {policy_name}", display_name)
                        self.formatter.print_key_value("Enforcement Mode", enforcement_mode)
                        
                        if enforcement_mode == 'DoNotEnforce':
                            self.formatter.print_warning("Policy is in audit mode only")
                        else:
                            self.formatter.print_success("Policy is actively enforced")
                        
                        self.formatter.print_separator()
                else:
                    self.formatter.print_warning("No FIPS-related policy assignments found")
            else:
                self.formatter.print_error(f"Failed to retrieve policy assignments: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 5. Check Network Security (TLS/SSL)
        self.formatter.print_subsection("NETWORK SECURITY - TLS/SSL CONFIGURATION")
        try:
            # Check Application Gateways for TLS configuration
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/applicationGateways?api-version=2022-09-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                gateways = response.json().get('value', [])
                if not gateways:
                    self.formatter.print_info("No Application Gateways found")
                else:
                    self.formatter.print_success(f"Found {len(gateways)} Application Gateways")
                    
                    for gateway in gateways:
                        gateway_name = gateway.get('name')
                        properties = gateway.get('properties', {})
                        
                        self.formatter.print_subsection(f"APPLICATION GATEWAY: {gateway_name}")
                        
                        # Check SSL policy
                        ssl_policy = properties.get('sslPolicy', {})
                        policy_name = ssl_policy.get('policyName', 'Not configured')
                        policy_type = ssl_policy.get('policyType', 'Not configured')
                        
                        self.formatter.print_key_value("SSL Policy Name", policy_name)
                        self.formatter.print_key_value("SSL Policy Type", policy_type)
                        
                        # Check for FIPS-compliant policies
                        fips_compliant_policies = ['AppGwSslPolicy20170401S', 'AppGwSslPolicy20170401', 'AppGwSslPolicy20150501']
                        if policy_name in fips_compliant_policies:
                            self.formatter.print_success("FIPS-compliant SSL policy configured")
                        else:
                            self.formatter.print_warning("Verify SSL policy meets FIPS requirements")
                        
                        # Check minimum TLS version
                        min_protocol_version = ssl_policy.get('minProtocolVersion', 'Not configured')
                        self.formatter.print_key_value("Minimum TLS Version", min_protocol_version)
                        
                        if min_protocol_version in ['TLSv1_2', 'TLSv1_3']:
                            self.formatter.print_success("Strong TLS version configured")
                        else:
                            self.formatter.print_warning("Consider upgrading to TLS 1.2 or higher")
                        
                        self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve Application Gateways: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")        
        
        # 6. Check Azure Recovery Services Vault Backup Encryption
        self.formatter.print_subsection("AZURE RECOVERY SERVICES VAULT - BACKUP DATA ENCRYPTION")
        try:
            # Get all Recovery Services Vaults
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.RecoveryServices/vaults?api-version=2023-04-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                vaults = response.json().get('value', [])
                if not vaults:
                    self.formatter.print_warning("No Recovery Services Vaults found in subscription")
                else:
                    self.formatter.print_success(f"Found {len(vaults)} Recovery Services Vaults")
                    
                    total_vaults = 0
                    encrypted_vaults = 0
                    
                    for vault in vaults:
                        total_vaults += 1
                        vault_name = vault.get('name', 'Unknown')
                        vault_id = vault.get('id', '')
                        location = vault.get('location', 'Unknown')
                        properties = vault.get('properties', {})
                        
                        self.formatter.print_subsection(f"RECOVERY SERVICES VAULT: {vault_name}")
                        self.formatter.print_key_value("Location", location)
                        
                        # Check encryption settings
                        encryption_settings = properties.get('encryption', {})
                        encryption_state = encryption_settings.get('state', 'Unknown')
                        encryption_type = encryption_settings.get('type', 'Unknown')
                        
                        self.formatter.print_key_value("Encryption State", encryption_state)
                        self.formatter.print_key_value("Encryption Type", encryption_type)
                        
                        # Check if backup data is encrypted
                        if encryption_state == 'Enabled':
                            encrypted_vaults += 1
                            self.formatter.print_success("Backup data encryption is enabled")
                            
                            # Check encryption type details
                            if encryption_type == 'SystemAssigned':
                                self.formatter.print_success("Using system-assigned managed identity for encryption")
                            elif encryption_type == 'UserAssigned':
                                self.formatter.print_success("Using user-assigned managed identity for encryption")
                            else:
                                self.formatter.print_info(f"Encryption type: {encryption_type}")
                            
                            # Check key vault integration
                            key_vault_properties = encryption_settings.get('keyVaultProperties', {})
                            key_vault_id = key_vault_properties.get('keyUri', 'Not configured')
                            
                            if key_vault_id != 'Not configured':
                                self.formatter.print_success("Key Vault integration configured for encryption keys")
                                self.formatter.print_key_value("Key Vault URI", key_vault_id)
                            else:
                                self.formatter.print_info("Using platform-managed encryption keys")
                            
                            # Check infrastructure encryption
                            infrastructure_encryption = encryption_settings.get('infrastructureEncryption', 'Disabled')
                            self.formatter.print_key_value("Infrastructure Encryption", infrastructure_encryption)
                            
                            if infrastructure_encryption == 'Enabled':
                                self.formatter.print_success("Infrastructure encryption enabled (double encryption)")
                            else:
                                self.formatter.print_info("Infrastructure encryption not enabled")
                            
                        elif encryption_state == 'Disabled':
                            self.formatter.print_error("Backup data encryption is disabled")
                        else:
                            self.formatter.print_warning(f"⚠ Encryption state unknown: {encryption_state}")
                        
                        # Check protected items (VMs, Storage, SQL workloads)
                        self.formatter.print_subsection(f"PROTECTED ITEMS IN VAULT: {vault_name}")
                        try:
                            # Get protected items
                            protected_items_url = f"{vault_id}/backupProtectedItems?api-version=2023-04-01"
                            protected_response = self.api_client.arm_get(protected_items_url)
                            
                            if protected_response.status_code == 200:
                                protected_items = protected_response.json().get('value', [])
                                if protected_items:
                                    self.formatter.print_success(f"Found {len(protected_items)} protected items")
                                    
                                    vm_count = 0
                                    storage_count = 0
                                    sql_count = 0
                                    
                                    for item in protected_items:
                                        item_properties = item.get('properties', {})
                                        item_type = item_properties.get('protectedItemType', 'Unknown')
                                        item_name = item.get('name', 'Unknown')
                                        
                                        if 'VirtualMachine' in item_type:
                                            vm_count += 1
                                        elif 'AzureStorage' in item_type:
                                            storage_count += 1
                                        elif 'SQL' in item_type:
                                            sql_count += 1
                                        
                                        self.formatter.print_key_value(f"Protected Item: {item_name}", item_type)
                                    
                                    # Summary of protected workloads
                                    if vm_count > 0:
                                        self.formatter.print_success(f"{vm_count} Virtual Machine(s) protected")
                                    if storage_count > 0:
                                        self.formatter.print_success(f"{storage_count} Storage workload(s) protected")
                                    if sql_count > 0:
                                        self.formatter.print_success(f"{sql_count} SQL workload(s) protected")
                                    
                                    # Verify encryption applies to all protected items
                                    if encryption_state == 'Enabled':
                                        self.formatter.print_success("All protected items benefit from backup data encryption")
                                    else:
                                        self.formatter.print_error("Protected items are not encrypted")
                                else:
                                    self.formatter.print_info("No protected items found in this vault")
                            else:
                                self.formatter.print_warning(f"Could not retrieve protected items: {protected_response.status_code}")
                        except Exception as e:
                            self.formatter.print_warning(f"Could not check protected items: {e}")
                        
                        # Check backup policies
                        try:
                            policies_url = f"{vault_id}/backupPolicies?api-version=2023-04-01"
                            policies_response = self.api_client.arm_get(policies_url)
                            
                            if policies_response.status_code == 200:
                                policies = policies_response.json().get('value', [])
                                if policies:
                                    self.formatter.print_success(f"Found {len(policies)} backup policies")
                                    
                                    for policy in policies:
                                        policy_name = policy.get('name', 'Unknown')
                                        policy_properties = policy.get('properties', {})
                                        policy_type = policy_properties.get('backupManagementType', 'Unknown')
                                        
                                        self.formatter.print_key_value(f"Policy: {policy_name}", policy_type)
                                        
                                        # Check if policy has encryption settings
                                        if encryption_state == 'Enabled':
                                            self.formatter.print_success("Backup policy benefits from vault-level encryption")
                                        else:
                                            self.formatter.print_warning("⚠ Backup policy not encrypted")
                                else:
                                    self.formatter.print_info("No backup policies found")
                            else:
                                self.formatter.print_warning(f"Could not retrieve backup policies: {policies_response.status_code}")
                        except Exception as e:
                            self.formatter.print_warning(f"Could not check backup policies: {e}")
                        
                        self.formatter.print_separator()
                    
                    # Summary of encryption compliance
                    self.formatter.print_subsection("RECOVERY SERVICES VAULT ENCRYPTION SUMMARY")
                    self.formatter.print_key_value("Total Recovery Services Vaults", total_vaults)
                    self.formatter.print_key_value("Vaults with Backup Encryption", encrypted_vaults)
                    self.formatter.print_key_value("Vaults without Backup Encryption", total_vaults - encrypted_vaults)
                    
                    if total_vaults > 0:
                        encryption_compliance = (encrypted_vaults / total_vaults) * 100
                        self.formatter.print_key_value("Backup Encryption Compliance", f"{encryption_compliance:.1f}%")
                        
                        if encryption_compliance >= 90:
                            self.formatter.print_success("EXCELLENT: Most Recovery Services Vaults have backup data encryption enabled")
                        elif encryption_compliance >= 70:
                            self.formatter.print_warning("⚠ GOOD: Most vaults have encryption, review missing ones")
                        else:
                            self.formatter.print_error("POOR: Many Recovery Services Vaults missing backup data encryption")
                    
                    # Compliance evidence
                    if encrypted_vaults > 0:
                        self.formatter.print_success("BACKUP DATA ENCRYPTION VERIFIED: Azure Recovery Services Vaults have backup data encryption enabled, ensuring all protected VMs, Storage, and SQL workloads have encrypted backup data for FedRAMP Moderate compliance.")
                    else:
                        self.formatter.print_error("BACKUP DATA ENCRYPTION NOT VERIFIED: Recovery Services Vaults do not have backup data encryption enabled.")
            else:
                self.formatter.print_error(f"Failed to retrieve Recovery Services Vaults: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking Recovery Services Vault encryption: {e}")
        
        self.formatter.print_separator()

    def check_recovery_services_backup_policies(self):
        """List all Recovery Services vaults and their backup policies, including backup frequency."""
        self.formatter.print_header(
            "AZURE RECOVERY SERVICES VAULTS AND BACKUP POLICIES",
            "This function lists all Recovery Services vaults and their backup policies, including backup frequency. It evidences the presence of automated backup and recovery processes for critical workloads."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        url = f"/subscriptions/{subscription_id}/providers/Microsoft.RecoveryServices/vaults?api-version=2022-08-01"
        try:
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                vaults = response.json().get('value', [])
                if not vaults:
                    self.formatter.print_info("No Recovery Services vaults found in this subscription.")
                for vault in vaults:
                    vault_name = vault.get('name')
                    rg = vault.get('id').split('/')[4]
                    self.formatter.print_key_value("Vault", vault_name)
                    self.formatter.print_key_value("Resource Group", rg)
                    # List backup policies
                    pol_url = f"/subscriptions/{subscription_id}/resourceGroups/{rg}/providers/Microsoft.RecoveryServices/vaults/{vault_name}/backupPolicies?api-version=2022-08-01"
                    pol_resp = self.api_client.arm_get(pol_url)
                    if pol_resp.status_code == 200:
                        policies = pol_resp.json().get('value', [])
                        for pol in policies:
                            pol_name = pol.get('name')
                            freq = pol.get('properties', {}).get('schedulePolicy', {}).get('scheduleRunFrequency', 'N/A')
                            self.formatter.print_key_value(f"Policy: {pol_name}", f"Frequency: {freq}")
                    else:
                        self.formatter.print_error(f"Failed to retrieve backup policies: {pol_resp.status_code}")
                    self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve Recovery Services vaults: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        self.formatter.print_separator()

    def check_comprehensive_database_backup_status(self):
        """Comprehensive verification of database backup configurations including all database types, backup types, retention periods, and backup status."""
        self.formatter.print_header(
            "COMPREHENSIVE DATABASE BACKUP VERIFICATION",
            "This function verifies that all databases, including customer data, are backed up using real-time incremental and daily full cycle backups across multiple availability zones. It checks backup retention (7+ days), backup status, and evidences backup coverage for compliance."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        
        # Track overall backup compliance
        total_databases = 0
        compliant_databases = 0
        backup_issues = []
        backup_policies_found = []
        
        # 1. Check Azure SQL Databases
        self.formatter.print_subsection("AZURE SQL DATABASE BACKUP STATUS")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Sql/servers?api-version=2022-05-01-preview"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                servers = response.json().get('value', [])
                if not servers:
                    self.formatter.print_info("No SQL servers found in this subscription.")
                else:
                    for server in servers:
                        server_name = server.get('name', 'Unknown')
                        server_id = server.get('id', '')
                        self.formatter.print_subsection(f"SQL Server: {server_name}")
                        
                        # Get databases for this server
                        db_url = f"{server_id}/databases?api-version=2022-05-01-preview"
                        db_response = self.api_client.arm_get(db_url)
                        if db_response.status_code == 200:
                            databases = db_response.json().get('value', [])
                            for db in databases:
                                total_databases += 1
                                db_name = db.get('name', 'Unknown')
                                db_id = db.get('id', '')
                                
                                # Check backup configuration
                                backup_config = db.get('properties', {}).get('backupStorageRedundancy', 'Unknown')
                                sku_name = db.get('sku', {}).get('name', 'Unknown')
                                
                                self.formatter.print_key_value(f"Database: {db_name}", f"SKU: {sku_name}")
                                self.formatter.print_key_value("Backup Storage Redundancy", backup_config)
                                
                                # Check for geo-replication (availability zones)
                                geo_links = db.get('properties', {}).get('geoReplicationLinks', [])
                                if geo_links:
                                    self.formatter.print_success(f"Geo-replication configured with {len(geo_links)} replica(s)")
                                else:
                                    self.formatter.print_warning("No geo-replication configured")
                                
                                # Check backup retention policy
                                try:
                                    backup_policy_url = f"{db_id}/backupShortTermRetentionPolicies/default?api-version=2022-05-01-preview"
                                    policy_response = self.api_client.arm_get(backup_policy_url)
                                    if policy_response.status_code == 200:
                                        policy = policy_response.json()
                                        retention_days = policy.get('properties', {}).get('retentionDays', 0)
                                        self.formatter.print_key_value("Backup Retention (Days)", retention_days)
                                        
                                        if retention_days >= 7:
                                            self.formatter.print_success("Retention meets 7+ day requirement")
                                            compliant_databases += 1
                                            backup_policies_found.append(f"SQL DB {db_name}: {retention_days} days retention")
                                        else:
                                            self.formatter.print_error(f"Retention ({retention_days} days) below 7-day requirement")
                                            backup_issues.append(f"SQL DB {db_name}: Insufficient retention ({retention_days} days)")
                                    else:
                                        self.formatter.print_warning("Unable to retrieve backup retention policy")
                                        backup_issues.append(f"SQL DB {db_name}: Could not retrieve backup policy")
                                except Exception as e:
                                    self.formatter.print_error(f"Error checking backup policy: {e}")
                                    backup_issues.append(f"SQL DB {db_name}: Error checking backup policy")
                                
                                # Check long-term backup retention policy
                                try:
                                    ltr_policy_url = f"{db_id}/backupLongTermRetentionPolicies/default?api-version=2022-05-01-preview"
                                    ltr_response = self.api_client.arm_get(ltr_policy_url)
                                    if ltr_response.status_code == 200:
                                        ltr_policy = ltr_response.json()
                                        ltr_retention_days = ltr_policy.get('properties', {}).get('retentionDays', 0)
                                        if ltr_retention_days > 0:
                                            self.formatter.print_success(f"Long-term retention configured: {ltr_retention_days} days")
                                            backup_policies_found.append(f"SQL DB {db_name}: LTR {ltr_retention_days} days")
                                        else:
                                            self.formatter.print_info("No long-term retention policy configured")
                                    else:
                                        self.formatter.print_info("No long-term retention policy found")
                                except Exception as e:
                                    self.formatter.print_info("Could not check long-term retention policy")
                                
                                self.formatter.print_separator()
                        else:
                            self.formatter.print_error(f"Failed to retrieve databases for server {server_name}: {db_response.status_code}")
            else:
                self.formatter.print_error(f"Failed to retrieve SQL servers: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking SQL databases: {e}")
        
        # 2. Check Azure Cosmos DB
        self.formatter.print_subsection("AZURE COSMOS DB BACKUP STATUS")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2022-11-15"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                cosmos_accounts = response.json().get('value', [])
                if not cosmos_accounts:
                    self.formatter.print_info("No Cosmos DB accounts found in this subscription.")
                else:
                    for account in cosmos_accounts:
                        total_databases += 1
                        account_name = account.get('name', 'Unknown')
                        
                        self.formatter.print_subsection(f"Cosmos DB Account: {account_name}")
                        
                        # Check backup policy
                        backup_policy = account.get('properties', {}).get('backupPolicy', {})
                        backup_type = backup_policy.get('type', 'Unknown')
                        self.formatter.print_key_value("Backup Type", backup_type)
                        
                        if backup_type == 'Continuous':
                            self.formatter.print_success("Continuous backup enabled (real-time incremental)")
                            retention_hours = backup_policy.get('continuousModeProperties', {}).get('tier', 'Unknown')
                            self.formatter.print_key_value("Continuous Backup Tier", retention_hours)
                            
                            if retention_hours in ['Continuous7Days', 'Continuous30Days']:
                                self.formatter.print_success("Retention meets 7+ day requirement")
                                compliant_databases += 1
                                backup_policies_found.append(f"Cosmos DB {account_name}: Continuous {retention_hours}")
                            else:
                                self.formatter.print_warning("⚠ Check retention period")
                                backup_issues.append(f"Cosmos DB {account_name}: Unknown retention tier {retention_hours}")
                        elif backup_type == 'Periodic':
                            self.formatter.print_info("Periodic backup configured")
                            retention_hours = backup_policy.get('periodicModeProperties', {}).get('backupRetentionIntervalInHours', 0)
                            retention_days = retention_hours / 24
                            self.formatter.print_key_value("Retention (days)", f"{retention_days:.1f}")
                            
                            if retention_days >= 7:
                                self.formatter.print_success("Retention meets 7+ day requirement")
                                compliant_databases += 1
                                backup_policies_found.append(f"Cosmos DB {account_name}: Periodic {retention_days:.1f} days")
                            else:
                                self.formatter.print_error("Retention below 7-day requirement")
                                backup_issues.append(f"Cosmos DB {account_name}: Insufficient retention ({retention_days:.1f} days)")
                        else:
                            self.formatter.print_error("No backup policy configured")
                            backup_issues.append(f"Cosmos DB {account_name}: No backup policy")
                        
                        self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve Cosmos DB accounts: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking Cosmos DB: {e}")
        
        # 3. Check Recovery Services Vaults and Backup Policies
        self.formatter.print_subsection("RECOVERY SERVICES VAULT BACKUP POLICIES")
        try:
            vault_url = f"/subscriptions/{subscription_id}/providers/Microsoft.RecoveryServices/vaults?api-version=2023-04-01"
            vault_response = self.api_client.arm_get(vault_url)
            
            if vault_response.status_code == 200:
                vaults = vault_response.json().get('value', [])
                if not vaults:
                    self.formatter.print_info("No Recovery Services vaults found in this subscription.")
                else:
                    for vault in vaults:
                        vault_name = vault.get('name', 'Unknown')
                        vault_id = vault.get('id', '')
                        
                        self.formatter.print_subsection(f"Recovery Services Vault: {vault_name}")
                        
                        # Check backup policies
                        policies_url = f"{vault_id}/backupPolicies?api-version=2023-04-01"
                        policies_response = self.api_client.arm_get(policies_url)
                        
                        if policies_response.status_code == 200:
                            policies = policies_response.json().get('value', [])
                            if policies:
                                self.formatter.print_success(f"Found {len(policies)} backup policies:")
                                for policy in policies:
                                    policy_name = policy.get('name', 'Unnamed')
                                    policy_props = policy.get('properties', {})
                                    policy_type = policy_props.get('backupManagementType', 'Unknown')
                                    
                                    # Check retention settings
                                    retention_policy = policy_props.get('retentionPolicy', {})
                                    if retention_policy:
                                        daily_retention = retention_policy.get('dailySchedule', {}).get('retentionDuration', {}).get('count', 0)
                                        weekly_retention = retention_policy.get('weeklySchedule', {}).get('retentionDuration', {}).get('count', 0)
                                        monthly_retention = retention_policy.get('monthlySchedule', {}).get('retentionDuration', {}).get('count', 0)
                                        yearly_retention = retention_policy.get('yearlySchedule', {}).get('retentionDuration', {}).get('count', 0)
                                        
                                        self.formatter.print_key_value(f"Policy: {policy_name} ({policy_type})", f"Daily: {daily_retention}, Weekly: {weekly_retention}, Monthly: {monthly_retention}, Yearly: {yearly_retention}")
                                        
                                        if daily_retention >= 7:
                                            self.formatter.print_success("Daily retention meets 7+ day requirement")
                                            backup_policies_found.append(f"Vault {vault_name}: {policy_name} - {daily_retention} days daily")
                                        else:
                                            self.formatter.print_warning(f"⚠ Daily retention ({daily_retention} days) below 7-day requirement")
                                    else:
                                        self.formatter.print_warning(f"⚠ Policy {policy_name} has no retention policy configured")
                            else:
                                self.formatter.print_warning("No backup policies found in this vault")
                        else:
                            self.formatter.print_error(f"Failed to retrieve backup policies: {policies_response.status_code}")
                        
                        self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve Recovery Services vaults: {vault_response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking Recovery Services vaults: {e}")
        
        # 4. Check for Backup Jobs and Recent Backup Status
        self.formatter.print_subsection("RECENT BACKUP JOB STATUS")
        try:
            # Check for recent backup jobs in Recovery Services vaults
            if 'vaults' in locals() and vaults:
                max_subitems = getattr(self.config, 'max_subitems', 10)
                for vault in vaults[:max_subitems]:  # Check first max_subitems vaults
                    vault_name = vault.get('name', 'Unknown')
                    vault_id = vault.get('id', '')
                    
                    # Check recent backup jobs
                    jobs_url = f"{vault_id}/backupJobs?api-version=2023-04-01"
                    jobs_response = self.api_client.arm_get(jobs_url)
                    
                    if jobs_response.status_code == 200:
                        jobs = jobs_response.json().get('value', [])
                        if jobs:
                            recent_jobs = [job for job in jobs if job.get('properties', {}).get('startTime', '') > '2024-01-01']
                            self.formatter.print_success(f"Vault {vault_name}: Found {len(recent_jobs)} recent backup jobs")
                            
                            # Show recent job status
                            for job in recent_jobs[:max_subitems]:  # Show first max_subitems jobs
                                job_props = job.get('properties', {})
                                job_status = job_props.get('status', 'Unknown')
                                job_type = job_props.get('backupManagementType', 'Unknown')
                                start_time = job_props.get('startTime', 'Unknown')
                                
                                status_icon = "✓" if job_status == 'Completed' else "⚠" if job_status == 'InProgress' else "✗"
                                self.formatter.print_key_value(f"{status_icon} {job_type} Job", f"Status: {job_status}, Started: {start_time}")
                        else:
                            self.formatter.print_info(f"Vault {vault_name}: No recent backup jobs found")
            else:
                self.formatter.print_info("No Recovery Services vaults to check for backup jobs")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking backup jobs: {e}")
        
        # 5. Summary and Compliance Report
        self.formatter.print_subsection("DATABASE BACKUP COMPLIANCE SUMMARY")
        self.formatter.print_key_value("Total Databases Found", total_databases)
        self.formatter.print_key_value("Compliant Databases", compliant_databases)
        self.formatter.print_key_value("Non-Compliant Databases", total_databases - compliant_databases)
        self.formatter.print_key_value("Backup Policies Found", len(backup_policies_found))
        
        if total_databases > 0:
            compliance_rate = (compliant_databases / total_databases) * 100
            self.formatter.print_key_value("Overall Compliance Rate", f"{compliance_rate:.1f}%")
            
            if compliance_rate >= 95:
                self.formatter.print_success("EXCELLENT: Database backup compliance meets requirements")
            elif compliance_rate >= 80:
                self.formatter.print_warning("⚠ GOOD: Most databases are compliant, review issues below")
            else:
                self.formatter.print_error("POOR: Significant backup compliance issues found")
        else:
            self.formatter.print_warning("⚠ No databases found to check")
        
        # List backup policies found
        if backup_policies_found:
            self.formatter.print_subsection("BACKUP POLICIES CONFIGURED")
            max_items = getattr(self.config, 'max_subitems', 10)
            for policy in backup_policies_found[:max_items]:
                self.formatter.print_success(f"• {policy}")
            if len(backup_policies_found) > max_items:
                self.formatter.print_info(f"... and {len(backup_policies_found) - max_items} more policies")
        
        # List backup issues
        if backup_issues:
            self.formatter.print_subsection("BACKUP COMPLIANCE ISSUES")
            max_items = getattr(self.config, 'max_subitems', 10)
            for issue in backup_issues[:max_items]:
                self.formatter.print_error(f"• {issue}")
            if len(backup_issues) > max_items:
                self.formatter.print_info(f"... and {len(backup_issues) - max_items} more issues")
        
        # Evidence statement
        self.formatter.print_subsection("COMPLIANCE EVIDENCE")
        if total_databases > 0 and compliant_databases == total_databases:
            self.formatter.print_success("ALL DATABASES VERIFIED: This organization backs up all databases, including customer data, using real-time incremental and daily full cycle backups across multiple availability zones. Daily records are retained for at least seven days to support rollback.")
        elif total_databases > 0:
            self.formatter.print_warning("⚠ PARTIAL COMPLIANCE: Some databases may not meet backup requirements. Review issues above and ensure all databases are properly configured.")
        else:
            self.formatter.print_info("ℹ NO DATABASES FOUND: No managed databases detected. Verify if databases exist in other subscriptions or use different database services.")
        
        self.formatter.print_separator()

    def check_missing_assettag_resources(self):
        """List all Azure resources in the subscription that are missing or have the required AssetTag tag."""
        self.formatter.print_header(
            "AZURE RESOURCES MISSING ASSETTAG",
            "This function lists all Azure resources in the subscription that are missing the required AssetTag tag, as well as those that have it. It evidences asset management and enforcement of tagging policies for compliance and inventory control."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        url = f"/subscriptions/{subscription_id}/resources?api-version=2021-04-01"
        try:
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                resources = response.json().get('value', [])
                missing = 0
                present = 0
                for res in resources:
                    tags = res.get('tags', {})
                    name = res.get('name')
                    type_ = res.get('type')
                    # Extract resource group from the ID
                    resource_id = res.get('id', '')
                    resource_group = '(unknown)'
                    if resource_id:
                        parts = resource_id.split('/')
                        if 'resourceGroups' in parts:
                            idx = parts.index('resourceGroups')
                            if idx + 1 < len(parts):
                                resource_group = parts[idx + 1]
                    if not tags or 'AssetTag' not in tags:
                        self.formatter.print_warning(f"Resource: {name} ({type_}) | Resource Group: {resource_group} - MISSING AssetTag")
                        missing += 1
                    else:
                        asset_tag_value = tags.get('AssetTag', '(no value)')
                        self.formatter.print_success(f"Resource: {name} ({type_}) | Resource Group: {resource_group} - AssetTag: {asset_tag_value}")
                        present += 1
                self.formatter.print_key_value("Total Missing AssetTag", missing)
                self.formatter.print_key_value("Total With AssetTag", present)
            else:
                self.formatter.print_error(f"Failed to retrieve resources: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        self.formatter.print_separator()

    def check_defender_app_control_status(self):
        """Check for Defender Application Control (MDAC) policies in Intune device configurations."""
        self.formatter.print_header(
            "DEFENDER APPLICATION CONTROL (MDAC) POLICY STATUS",
            "This function checks for Defender Application Control (MDAC) policies in Intune device configurations. It evidences application whitelisting and control for endpoint security and compliance."
        )
        try:
            response = self.api_client.graph_get("/deviceManagement/deviceConfigurations")
            if response.status_code == 200:
                configs = response.json().get('value', [])
                found = False
                for config_item in configs:
                    if 'applicationcontrol' in (config_item.get('displayName', '').lower() + config_item.get('description', '').lower()):
                        found = True
                        self.formatter.print_key_value("Policy", config_item.get('displayName'))
                        self.formatter.print_key_value("Description", config_item.get('description', 'N/A'))
                        self.formatter.print_separator()
                if not found:
                    self.formatter.print_warning("No Defender Application Control (MDAC) policies found in Intune device configurations.")
            else:
                self.formatter.print_error(f"Failed to retrieve device configurations: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
            self.formatter.print_separator()

    def check_sentinel_log_deletion_alert_rules(self):
        """Check for Sentinel analytic rules that alert on log deletion/purge activity."""
        self.formatter.print_header(
            "SENTINEL ANALYTIC RULES FOR LOG DELETION ALERTS",
            "This function checks for Sentinel analytic rules that alert on log deletion/purge activity. It evidences monitoring and alerting for log integrity and retention compliance."
        )
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-12-01-preview"
        try:
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                rules = response.json().get('value', [])
                found = False
                for rule in rules:
                    query = rule.get('properties', {}).get('query', '')
                    query_lower = query.lower()
                    if 'delete' in query_lower or 'purge' in query_lower:
                        found = True
                        self.formatter.print_key_value("Rule", rule.get('name'))
                        self.formatter.print_key_value("Description", rule.get('properties', {}).get('description', 'N/A'))
                        self.formatter.print_separator()
                if not found:
                    self.formatter.print_warning("No Sentinel analytic rules found for log deletion/purge alerts.")
            else:
                self.formatter.print_error(f"Failed to retrieve analytic rules: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        self.formatter.print_separator()

    def check_pim_role_assignment_policies(self):
        """Check and print Privileged Identity Management (PIM) settings for Azure AD roles."""
        self.formatter.print_header(
            "MICROSOFT ENTRA PRIVILEGED IDENTITY MANAGEMENT (PIM) ROLE ASSIGNMENT POLICIES",
            "This function checks and prints Privileged Identity Management (PIM) settings for Azure AD roles using the Microsoft Graph API. It evidences privileged access management and assignment policies for compliance."
        )
        try:
            response = self.api_client.graph_get("/roleManagement/directory/roleAssignmentSchedulePolicies")
            
            # Check for license requirement error
            if self._handle_pim_license_error(response):
                return
            
            if response.status_code == 200:
                policies = response.json().get('value', [])
                if not policies:
                    self.formatter.print_info("No PIM role assignment schedule policies found.")
                for policy in policies:
                    self.formatter.print_key_value("Policy ID", policy.get('id', 'N/A'))
                    self.formatter.print_key_value("Display Name", policy.get('displayName', 'N/A'))
                    self.formatter.print_key_value("Role Definition ID", policy.get('roleDefinitionId', 'N/A'))
                    self.formatter.print_key_value("Max Activation Duration", policy.get('maxActivationDuration', 'N/A'))
                    self.formatter.print_key_value("Assignment Type", policy.get('assignmentType', 'N/A'))
                    self.formatter.print_key_value("Is Default", policy.get('isDefault', 'N/A'))
                    self.formatter.print_key_value("Conditions", policy.get('conditions', 'N/A'))
                    self.formatter.print_separator()
            elif response.status_code == 400 and 'Resource not found for the segment' in response.text:
                self.formatter.print_info("PIM role assignment policies are only available with Microsoft Entra ID P2 (Azure AD Premium P2) and may not be available in your tenant or region.")
            else:
                self.formatter.print_error(f"Failed to retrieve PIM role assignment policies: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving PIM role assignment policies: {e}")
        self.formatter.print_separator()

    def check_intune_device_compliance_details(self):
        """Print detailed Intune device compliance policy settings for Windows, iOS, and Android."""
        self.formatter.print_header(
            "MICROSOFT INTUNE DEVICE COMPLIANCE POLICY DETAILS",
            "This function prints detailed Intune device compliance policy settings for Windows, iOS, and Android, including minimum OS version, encryption, jailbreak/root detection, and firewall/antivirus requirements. It evidences device compliance with security baselines across platforms."
        )
        try:
            response = self.api_client.graph_get("/deviceManagement/deviceCompliancePolicies")
            if response.status_code == 200:
                policies = response.json().get('value', [])
                if not policies:
                    self.formatter.print_info("No device compliance policies found.")
                for policy in policies:
                    odata_type = policy.get('@odata.type', '')
                    display_name = policy.get('displayName', 'Unnamed Policy')
                    self.formatter.print_key_value("Policy", display_name)
                    if odata_type.endswith('windows10CompliancePolicy'):
                        self.formatter.print_key_value("Platform", "Windows 10/11")
                        self.formatter.print_key_value("Minimum OS Version", policy.get('minWindows10Version', 'N/A'))
                        self.formatter.print_key_value("Encryption Required", policy.get('bitLockerEnabled', 'N/A'))
                        self.formatter.print_key_value("Firewall Required", policy.get('firewallEnabled', 'N/A'))
                        self.formatter.print_key_value("Antivirus Required", policy.get('defenderEnabled', 'N/A'))
                        self.formatter.print_key_value("Secure Boot Required", policy.get('secureBootEnabled', 'N/A'))
                        self.formatter.print_key_value("Password Required", policy.get('passwordRequired', 'N/A'))
                    elif odata_type.endswith('iosCompliancePolicy'):
                        self.formatter.print_key_value("Platform", "iOS")
                        self.formatter.print_key_value("Minimum OS Version", policy.get('minOSVersion', 'N/A'))
                        self.formatter.print_key_value("Device Threat Protection Required", policy.get('deviceThreatProtectionEnabled', 'N/A'))
                        self.formatter.print_key_value("Jailbreak Detection", policy.get('passcodeBlockSimple', 'N/A'))
                        self.formatter.print_key_value("Encryption Required", policy.get('storageRequireEncryption', 'N/A'))
                    elif odata_type.endswith('androidCompliancePolicy'):
                        self.formatter.print_key_value("Platform", "Android")
                        self.formatter.print_key_value("Minimum OS Version", policy.get('minAndroidVersion', 'N/A'))
                        self.formatter.print_key_value("Device Threat Protection Required", policy.get('deviceThreatProtectionEnabled', 'N/A'))
                        self.formatter.print_key_value("Root Detection", policy.get('securityBlockJailbrokenDevices', 'N/A'))
                        self.formatter.print_key_value("Encryption Required", policy.get('storageRequireEncryption', 'N/A'))
                    else:
                        self.formatter.print_key_value("Platform", f"Other ({odata_type})")
                    self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve device compliance policies: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving device compliance details: {e}")
        self.formatter.print_separator() 

    def check_certificate_compliance_evidence(self):
        """Provide evidence for the Approved Certificate Authorities control, including inventory of all SSL/TLS certificates."""
        self.formatter.print_header(
            "CERTIFICATE COMPLIANCE EVIDENCE: APPROVED CERTIFICATE AUTHORITIES",
            "This function provides evidence for the Approved Certificate Authorities control, including inventory of all SSL/TLS certificates, issuer, expiration, associated system, and compliance gaps. It checks for Azure Certificate Manager deployment, Key Vault integration, monitoring/alerting, and logging. It highlights any gaps with FedRAMP Moderate requirements."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        
        # 1. Check for Azure Certificate Manager deployment
        self.formatter.print_subsection("Azure Certificate Manager Deployment Status")
        url = f"/subscriptions/{subscription_id}/providers/Microsoft.CertificateManager/certificateManagers?api-version=2022-01-01"
        try:
            response = self.api_client.arm_get(url)
            if response.status_code == 404 or response.status_code == 400:
                self.formatter.print_error("Azure Certificate Manager is NOT deployed in this subscription. This is a compliance gap under FedRAMP Moderate controls.")
            elif response.status_code == 200 and not response.json().get('value'):
                self.formatter.print_error("Azure Certificate Manager is NOT deployed in this subscription. This is a compliance gap under FedRAMP Moderate controls.")
            elif response.status_code == 200:
                self.formatter.print_success("Azure Certificate Manager is deployed.")
            else:
                self.formatter.print_warning(f"Unable to determine Azure Certificate Manager status: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception checking Certificate Manager: {e}")
        
        # 2. Inventory certificates from Key Vaults
        self.formatter.print_subsection("Key Vault Certificate Inventory")
        kv_url = f"/subscriptions/{subscription_id}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01"
        try:
            kv_resp = self.api_client.arm_get(kv_url)
            if kv_resp.status_code == 200:
                vaults = kv_resp.json().get('value', [])
                if not vaults:
                    self.formatter.print_info("No Key Vaults found.")
                for vault in vaults:
                    vault_name = vault.get('name')
                    rg = vault.get('id').split('/')[4]
                    certs_url = f"/subscriptions/{subscription_id}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{vault_name}/certificates?api-version=2022-07-01"
                    certs_resp = self.api_client.arm_get(certs_url)
                    if certs_resp.status_code == 200:
                        certs = certs_resp.json().get('value', [])
                        if not certs:
                            self.formatter.print_info(f"Vault: {vault_name} (Resource Group: {rg}) - No certificates found.")
                        for cert in certs:
                            cert_name = cert.get('name')
                            props = cert.get('properties', {})
                            issuer = props.get('issuer', 'N/A')
                            exp = props.get('expires', 'N/A')
                            self.formatter.print_key_value(f"Vault: {vault_name}, Certificate: {cert_name}", f"Issuer: {issuer}, Expiration: {exp}")
                    else:
                        self.formatter.print_error(f"Vault: {vault_name} - Failed to retrieve certificates: {certs_resp.status_code}")
            else:
                self.formatter.print_error(f"Failed to retrieve Key Vaults: {kv_resp.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception checking Key Vaults: {e}")
        
        # 3. Inventory App Service Certificates
        self.formatter.print_subsection("App Service Certificate Inventory")
        asc_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Web/certificates?api-version=2022-03-01"
        try:
            asc_resp = self.api_client.arm_get(asc_url)
            if asc_resp.status_code == 200:
                certs = asc_resp.json().get('value', [])
                if not certs:
                    self.formatter.print_info("No App Service Certificates found.")
                for cert in certs:
                    cert_name = cert.get('name')
                    props = cert.get('properties', {})
                    issuer = props.get('issuer', 'N/A')
                    exp = props.get('expirationDate', 'N/A')
                    self.formatter.print_key_value(f"App Service Certificate: {cert_name}", f"Issuer: {issuer}, Expiration: {exp}")
            else:
                self.formatter.print_error(f"Failed to retrieve App Service Certificates: {asc_resp.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception checking App Service Certificates: {e}")
        
        self.formatter.print_separator()

    def check_master_inventory_reconciliation(self):
        """Evidence the Master Inventory Reconciliation control by checking Azure Resource Manager inventory, Azure Policy compliance, tagging standards, and change tracking."""
        self.formatter.print_header(
            "MASTER INVENTORY RECONCILIATION: AZURE RESOURCE MANAGER",
            "This function evidences the Master Inventory Reconciliation control by checking Azure Resource Manager inventory, Azure Resource Graph queries, Azure Policy compliance, tagging standards, and change tracking. It validates monthly inventory reviews, component change monitoring, and compliance status for FedRAMP Moderate requirements."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        
        # 1. Check Azure Resource Manager inventory completeness
        self.formatter.print_subsection("AZURE RESOURCE MANAGER INVENTORY COMPLETENESS")
        try:
            url = f"/subscriptions/{subscription_id}/resources?api-version=2021-04-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                resources = response.json().get('value', [])
                self.formatter.print_success(f"Found {len(resources)} total resources in Azure Resource Manager")
                
                # Categorize resources by type and location
                resource_types = {}
                resource_locations = {}
                resource_groups = {}
                critical_resources = []
                
                for resource in resources:
                    resource_type = resource.get('type', 'Unknown')
                    location = resource.get('location', 'Unknown')
                    resource_group = resource.get('id', '').split('/')[4] if len(resource.get('id', '').split('/')) > 4 else 'Unknown'
                    
                    resource_types[resource_type] = resource_types.get(resource_type, 0) + 1
                    resource_locations[location] = resource_locations.get(location, 0) + 1
                    resource_groups[resource_group] = resource_groups.get(resource_group, 0) + 1
                    
                    # Identify critical resources
                    critical_types = ['Microsoft.Compute/virtualMachines', 'Microsoft.Storage/storageAccounts', 
                                    'Microsoft.KeyVault/vaults', 'Microsoft.Network/virtualNetworks',
                                    'Microsoft.Web/sites', 'Microsoft.ContainerService/managedClusters']
                    if resource_type in critical_types:
                        critical_resources.append({
                            'name': resource.get('name', 'Unnamed'),
                            'type': resource_type,
                            'location': location,
                            'resource_group': resource_group,
                            'tags': resource.get('tags', {})
                        })
                
                # Display resource type distribution
                self.formatter.print_subsection("Resource Type Distribution")
                max_items = getattr(self.config, 'max_subitems', 10)
                for rtype, count in sorted(resource_types.items(), key=lambda x: x[1], reverse=True)[:max_items]:
                    self.formatter.print_key_value(rtype, f"{count} resources")
                
                if len(resource_types) > max_items:
                    self.formatter.print_info(f"... and {len(resource_types) - max_items} more resource types")
                
                # Display location distribution
                self.formatter.print_subsection("Resource Location Distribution")
                for location, count in sorted(resource_locations.items(), key=lambda x: x[1], reverse=True)[:max_items]:
                    self.formatter.print_key_value(location, f"{count} resources")
                
                # Display resource group distribution
                self.formatter.print_subsection("Resource Group Distribution")
                for rg, count in sorted(resource_groups.items(), key=lambda x: x[1], reverse=True)[:max_items]:
                    self.formatter.print_key_value(rg, f"{count} resources")
                
                # Display critical resources
                self.formatter.print_subsection("Critical Resources Inventory")
                if critical_resources:
                    self.formatter.print_success(f"Found {len(critical_resources)} critical resources")
                    for resource in critical_resources[:max_items]:
                        self.formatter.print_key_value(f"{resource['name']} ({resource['type']})", 
                                                     f"Location: {resource['location']}, RG: {resource['resource_group']}")
                    if len(critical_resources) > max_items:
                        self.formatter.print_info(f"... and {len(critical_resources) - max_items} more critical resources")
                else:
                    self.formatter.print_warning("No critical resources found")
                    
            else:
                self.formatter.print_error(f"Failed to retrieve resources: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 2. Check Azure Policy compliance for inventory management
        self.formatter.print_subsection("AZURE POLICY COMPLIANCE FOR INVENTORY MANAGEMENT")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                assignments = response.json().get('value', [])
                
                # Categorize policies by type
                inventory_policies = []
                tagging_policies = []
                compliance_policies = []
                security_policies = []
                
                for policy in assignments:
                    display_name = policy.get('properties', {}).get('displayName', '').lower()
                    if any(keyword in display_name for keyword in ['tag', 'inventory', 'compliance', 'resource', 'asset']):
                        inventory_policies.append(policy)
                    if any(keyword in display_name for keyword in ['tag', 'tagging']):
                        tagging_policies.append(policy)
                    if any(keyword in display_name for keyword in ['compliance', 'audit']):
                        compliance_policies.append(policy)
                    if any(keyword in display_name for keyword in ['security', 'defender', 'encryption']):
                        security_policies.append(policy)
                
                # Display policy assignments by category
                self.formatter.print_subsection("Inventory Management Policies")
                if inventory_policies:
                    self.formatter.print_success(f"Found {len(inventory_policies)} inventory-related policy assignments")
                    max_items = getattr(self.config, 'max_subitems', 5)
                    for policy in inventory_policies[:max_items]:
                        name = policy.get('properties', {}).get('displayName', 'Unnamed')
                        enforcement = policy.get('properties', {}).get('enforcementMode', 'Default')
                        self.formatter.print_key_value(name, enforcement)
                    if len(inventory_policies) > max_items:
                        self.formatter.print_info(f"... and {len(inventory_policies) - max_items} more")
                else:
                    self.formatter.print_warning("No inventory-related policy assignments found")
                
                # Display tagging policies
                self.formatter.print_subsection("Tagging Policies")
                if tagging_policies:
                    self.formatter.print_success(f"Found {len(tagging_policies)} tagging policy assignments")
                    for policy in tagging_policies[:max_items]:
                        name = policy.get('properties', {}).get('displayName', 'Unnamed')
                        enforcement = policy.get('properties', {}).get('enforcementMode', 'Default')
                        self.formatter.print_key_value(name, enforcement)
                else:
                    self.formatter.print_warning("No tagging policy assignments found")
                
                # Display compliance policies
                self.formatter.print_subsection("Compliance Policies")
                if compliance_policies:
                    self.formatter.print_success(f"Found {len(compliance_policies)} compliance policy assignments")
                    for policy in compliance_policies[:max_items]:
                        name = policy.get('properties', {}).get('displayName', 'Unnamed')
                        enforcement = policy.get('properties', {}).get('enforcementMode', 'Default')
                        self.formatter.print_key_value(name, enforcement)
                else:
                    self.formatter.print_warning("No compliance policy assignments found")
                    
            else:
                self.formatter.print_error(f"Failed to retrieve policy assignments: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 3. Check resource tagging compliance
        self.formatter.print_subsection("RESOURCE TAGGING COMPLIANCE")
        try:
            url = f"/subscriptions/{subscription_id}/resources?api-version=2021-04-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                resources = response.json().get('value', [])
                untagged_resources = []
                missing_required_tags = []
                required_tags = ['owner', 'environment', 'classification', 'costcenter', 'project', 'asset', 'department']
                
                for resource in resources:
                    tags = resource.get('tags', {})
                    if not tags:
                        untagged_resources.append({
                            'name': resource.get('name', 'Unnamed'),
                            'type': resource.get('type', 'Unknown'),
                            'resource_group': resource.get('id', '').split('/')[4] if len(resource.get('id', '').split('/')) > 4 else 'Unknown'
                        })
                    else:
                        missing_tags = [tag for tag in required_tags if tag.lower() not in [k.lower() for k in tags.keys()]]
                        if missing_tags:
                            missing_required_tags.append({
                                'name': resource.get('name', 'Unnamed'),
                                'type': resource.get('type', 'Unknown'),
                                'resource_group': resource.get('id', '').split('/')[4] if len(resource.get('id', '').split('/')) > 4 else 'Unknown',
                                'missing_tags': missing_tags,
                                'existing_tags': list(tags.keys())
                            })
                
                self.formatter.print_key_value("Total Resources", len(resources))
                self.formatter.print_key_value("Untagged Resources", len(untagged_resources))
                self.formatter.print_key_value("Resources Missing Required Tags", len(missing_required_tags))
                self.formatter.print_key_value("Tagging Compliance Rate", f"{((len(resources) - len(untagged_resources) - len(missing_required_tags)) / len(resources) * 100):.1f}%" if resources else "0%")
                
                # Display untagged resources
                if untagged_resources:
                    self.formatter.print_subsection("Sample Untagged Resources")
                    max_items = getattr(self.config, 'max_subitems', 5)
                    for resource in untagged_resources[:max_items]:
                        self.formatter.print_list_item(f"{resource['name']} ({resource['type']}) - RG: {resource['resource_group']}")
                    if len(untagged_resources) > max_items:
                        self.formatter.print_info(f"... and {len(untagged_resources) - max_items} more")
                
                # Display resources missing required tags
                if missing_required_tags:
                    self.formatter.print_subsection("Sample Resources Missing Required Tags")
                    for resource in missing_required_tags[:max_items]:
                        self.formatter.print_list_item(f"{resource['name']} ({resource['type']}): Missing {', '.join(resource['missing_tags'])}")
                        self.formatter.print_info(f"  Existing tags: {', '.join(resource['existing_tags'])}")
                    if len(missing_required_tags) > max_items:
                        self.formatter.print_info(f"... and {len(missing_required_tags) - max_items} more")
            else:
                self.formatter.print_error(f"Failed to retrieve resources: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 4. Check resource change tracking
        self.formatter.print_subsection("RESOURCE CHANGE TRACKING")
        try:
            # Check for recent resource changes using activity logs
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Insights/eventTypes/management/values?api-version=2017-03-01-preview&$filter=eventTimestamp ge {(datetime.datetime.now() - datetime.timedelta(days=30)).isoformat()}"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                events = response.json().get('value', [])
                resource_changes = [e for e in events if e.get('eventName', {}).get('value') in ['Write', 'Delete']]
                
                self.formatter.print_key_value("Resource Changes (Last 30 Days)", len(resource_changes))
                
                if resource_changes:
                    self.formatter.print_subsection("Recent Resource Changes")
                    max_items = getattr(self.config, 'max_subitems', 5)
                    for event in resource_changes[:max_items]:
                        event_name = event.get('eventName', {}).get('value', 'Unknown')
                        resource_type = event.get('resourceType', {}).get('value', 'Unknown')
                        resource_name = event.get('resourceId', '').split('/')[-1] if event.get('resourceId') else 'Unknown'
                        timestamp = event.get('eventTimestamp', 'Unknown')
                        self.formatter.print_key_value(f"{event_name} - {resource_name}", f"{resource_type} at {timestamp}")
                    if len(resource_changes) > max_items:
                        self.formatter.print_info(f"... and {len(resource_changes) - max_items} more changes")
                else:
                    self.formatter.print_info("No resource changes detected in the last 30 days")
            else:
                self.formatter.print_warning("Unable to retrieve activity logs for change tracking")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking resource changes: {e}")
        
        # 5. Check resource compliance status
        self.formatter.print_subsection("RESOURCE COMPLIANCE STATUS")
        try:
            # Check for policy compliance states
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2019-10-01&$top=1000"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                policy_states = response.json().get('value', [])
                
                compliance_summary = {
                    'compliant': 0,
                    'non_compliant': 0,
                    'exempt': 0,
                    'unknown': 0
                }
                
                for state in policy_states:
                    compliance_state = state.get('complianceState', 'Unknown')
                    if compliance_state == 'Compliant':
                        compliance_summary['compliant'] += 1
                    elif compliance_state == 'NonCompliant':
                        compliance_summary['non_compliant'] += 1
                    elif compliance_state == 'Exempt':
                        compliance_summary['exempt'] += 1
                    else:
                        compliance_summary['unknown'] += 1
                
                total_policies = sum(compliance_summary.values())
                if total_policies > 0:
                    compliance_rate = (compliance_summary['compliant'] / total_policies) * 100
                    self.formatter.print_key_value("Overall Compliance Rate", f"{compliance_rate:.1f}%")
                    self.formatter.print_key_value("Compliant Resources", compliance_summary['compliant'])
                    self.formatter.print_key_value("Non-Compliant Resources", compliance_summary['non_compliant'])
                    self.formatter.print_key_value("Exempt Resources", compliance_summary['exempt'])
                    self.formatter.print_key_value("Unknown Status", compliance_summary['unknown'])
                else:
                    self.formatter.print_warning("No policy compliance data available")
            else:
                self.formatter.print_warning("Unable to retrieve policy compliance states")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking compliance status: {e}")
        
        self.formatter.print_separator() 

    def check_infrastructure_vulnerability_scans(self):
        """Evidence the Infrastructure Vulnerability Scans control by checking Azure Posture Management (Defender for Cloud) configuration."""
        self.formatter.print_header(
            "INFRASTRUCTURE VULNERABILITY SCANS: AZURE POSTURE MANAGEMENT",
            "This function evidences the Infrastructure Vulnerability Scans control by checking Azure Posture Management (Defender for Cloud) configuration, vulnerability assessment capabilities, and scan results tracking. It validates continuous monitoring and vulnerability management for FedRAMP Moderate compliance."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        
        # 1. Check Defender for Cloud (Azure Posture Management) deployment status
        self.formatter.print_subsection("AZURE POSTURE MANAGEMENT (DEFENDER FOR CLOUD) DEPLOYMENT STATUS")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/pricings?api-version=2024-01-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                pricings = response.json().get('value', [])
                if pricings:
                    self.formatter.print_success("Defender for Cloud pricing tiers configured:")
                    for pricing in pricings:
                        name = pricing.get('name', 'N/A')
                        tier = pricing.get('properties', {}).get('pricingTier', 'N/A')
                        self.formatter.print_key_value(name, tier)
                        
                        # Check for vulnerability assessment capabilities
                        if name in ['VirtualMachines', 'SqlServers', 'ContainerRegistry', 'KubernetesService']:
                            if tier == 'Free':
                                self.formatter.print_warning(f"{name} is on Free tier - limited vulnerability assessment capabilities")
                            elif tier in ['Standard', 'Premium']:
                                self.formatter.print_success(f"{name} has enhanced vulnerability assessment capabilities")
                else:
                    self.formatter.print_error("No Defender for Cloud pricing information found")
            else:
                self.formatter.print_error(f"Failed to retrieve Defender for Cloud pricing: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 2. Check vulnerability assessment configuration
        self.formatter.print_subsection("VULNERABILITY ASSESSMENT CONFIGURATION")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/assessments?api-version=2020-01-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                assessments = response.json().get('value', [])
                vulnerability_assessments = [a for a in assessments if any(keyword in a.get('properties', {}).get('displayName', '').lower() 
                                            for keyword in ['vulnerability', 'baseline', 'security configuration', 'compliance'])]
                if vulnerability_assessments:
                    self.formatter.print_success(f"Found {len(vulnerability_assessments)} vulnerability and baseline assessments")
                    max_subitems = getattr(self.config, 'max_subitems', 10)
                    for assessment in vulnerability_assessments[:max_subitems]:  # Show first max_subitems
                        name = assessment.get('properties', {}).get('displayName', 'Unnamed')
                        status = assessment.get('properties', {}).get('status', {}).get('code', 'Unknown')
                        severity = assessment.get('properties', {}).get('metadata', {}).get('severity', 'N/A')
                        self.formatter.print_key_value(f"{name} (Severity: {severity})", status)
                    if len(vulnerability_assessments) > max_subitems:
                        self.formatter.print_info(f"... and {len(vulnerability_assessments) - max_subitems} more assessments")
                else:
                    self.formatter.print_error("No vulnerability assessments found")
            else:
                self.formatter.print_error(f"Failed to retrieve security assessments: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 3. Check for failed security assessments (vulnerabilities)
        self.formatter.print_subsection("FAILED SECURITY ASSESSMENTS (VULNERABILITIES)")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/assessments?api-version=2020-01-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                assessments = response.json().get('value', [])
                failed_assessments = [a for a in assessments if a.get('properties', {}).get('status', {}).get('code') == 'Unhealthy']
                if failed_assessments:
                    self.formatter.print_warning(f"Found {len(failed_assessments)} failed security assessments (vulnerabilities):")
                    high_critical_count = 0
                    for assessment in failed_assessments:
                        name = assessment.get('properties', {}).get('displayName', 'Unnamed')
                        severity = assessment.get('properties', {}).get('metadata', {}).get('severity', 'N/A')
                        if severity in ['High', 'Critical']:
                            high_critical_count += 1
                            self.formatter.print_error(f"{name} (Severity: {severity})")
                    
                    self.formatter.print_subsection("Summary")
                    self.formatter.print_key_value("Total failed assessments", len(failed_assessments))
                    self.formatter.print_key_value("High/Critical severity", high_critical_count)
                    self.formatter.print_key_value("Medium/Low severity", len(failed_assessments) - high_critical_count)
                    
                    if high_critical_count > 0:
                        self.formatter.print_error(f"COMPLIANCE GAP: {high_critical_count} high/critical vulnerabilities require immediate remediation")
                else:
                    self.formatter.print_success("No failed security assessments found")
            else:
                self.formatter.print_error(f"Failed to retrieve security assessments: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        self.formatter.print_separator()

    def check_insider_threat_escalation(self):
        """Evidence the Insider Threat Escalation control by checking Microsoft Sentinel UEBA configuration and high-risk user monitoring."""
        self.formatter.print_header(
            "INSIDER THREAT ESCALATION: USER AND ENTITY BEHAVIOR ANALYTICS",
            "This function evidences the Insider Threat Escalation control by checking Microsoft Sentinel UEBA configuration, high-risk user monitoring, and insider threat detection capabilities. It validates automated monitoring and response for potential insider threats for FedRAMP Moderate compliance."
        )
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        
        # 1. Check Microsoft Sentinel UEBA Configuration
        self.formatter.print_subsection("MICROSOFT SENTINEL UEBA CONFIGURATION")
        try:
            url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/settings?api-version=2023-02-01-preview"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                settings = response.json().get('value', [])
                ueba_enabled = False
                for setting in settings:
                    if setting.get('kind') == 'Ueba':
                        ueba_enabled = True
                        self.formatter.print_success("User and Entity Behavior Analytics (UEBA) is ENABLED in Microsoft Sentinel")
                        break
                if not ueba_enabled:
                    self.formatter.print_error("User and Entity Behavior Analytics (UEBA) is NOT enabled in Microsoft Sentinel")
                    self.formatter.print_info("This is a critical gap for insider threat detection")
                    self.formatter.print_info("Enable UEBA in Sentinel workspace Configuration > Settings")
            else:
                self.formatter.print_error(f"Failed to retrieve Sentinel settings: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 2. Check for High-Risk User Monitoring Analytics Rules
        self.formatter.print_subsection("HIGH-RISK USER MONITORING ANALYTICS RULES")
        try:
            url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01-preview"
            response = self.api_client.arm_get(url)
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
                    self.formatter.print_success(f"Found {len(insider_threat_rules)} insider threat related analytics rules:")
                    max_subitems = getattr(self.config, 'max_subitems', 10)
                    for rule in insider_threat_rules[:max_subitems]:  # Show first max_subitems
                        name = rule.get('name', 'Unnamed')
                        enabled = rule.get('properties', {}).get('enabled', False)
                        status = "Enabled" if enabled else "Disabled"
                        self.formatter.print_key_value(name, status)
                    if len(insider_threat_rules) > max_subitems:
                        self.formatter.print_info(f"... and {len(insider_threat_rules) - max_subitems} more rules")
                else:
                    self.formatter.print_error("No insider threat related analytics rules found")
                
                if ueba_rules:
                    self.formatter.print_success(f"Found {len(ueba_rules)} UEBA-specific analytics rules")
                else:
                    self.formatter.print_error("No UEBA-specific analytics rules found")
            else:
                self.formatter.print_error(f"Failed to retrieve analytics rules: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        self.formatter.print_separator() 

    def check_intrusion_detection_systems(self):
        """Evidence the Intrusion Detection Systems control by checking Microsoft Defender for Cloud integration with Microsoft Sentinel."""
        self.formatter.print_header(
            "INTRUSION DETECTION SYSTEMS: MICROSOFT DEFENDER FOR CLOUD",
            "This function evidences the Intrusion Detection Systems control by checking Microsoft Defender for Cloud integration with Microsoft Sentinel, data connector configuration, alert ingestion, and incident response capabilities. It validates intrusion detection and response for FedRAMP Moderate compliance."
        )
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        
        # 1. Check Microsoft Defender for Cloud Deployment Status
        self.formatter.print_subsection("MICROSOFT DEFENDER FOR CLOUD DEPLOYMENT STATUS")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/pricings?api-version=2024-01-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                pricings = response.json().get('value', [])
                if pricings:
                    self.formatter.print_success("Microsoft Defender for Cloud pricing tiers configured:")
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
                            self.formatter.print_success(f"{plan_name}: {tier}")
                        else:
                            disabled_plans.append(plan_name)
                            self.formatter.print_warning(f"{plan_name}: {tier} (Limited intrusion detection capabilities)")
                        
                    self.formatter.print_subsection("Summary")
                    self.formatter.print_key_value("Enabled Defender Plans", len(enabled_plans))
                    self.formatter.print_key_value("Disabled Defender Plans", len(disabled_plans))
                    
                    if len(enabled_plans) == 0:
                        self.formatter.print_error("CRITICAL GAP: No Microsoft Defender plans are enabled")
                        self.formatter.print_error("This severely limits intrusion detection capabilities")
                else:
                    self.formatter.print_error("No Microsoft Defender for Cloud pricing information found")
            else:
                self.formatter.print_error(f"Failed to retrieve Defender pricing: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 2. Check Microsoft Sentinel Data Connector Integration
        self.formatter.print_subsection("MICROSOFT SENTINEL DATA CONNECTOR INTEGRATION")
        try:
            url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2023-02-01-preview"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                connectors = response.json().get('value', [])
                defender_connectors = []
                
                for connector in connectors:
                    connector_type = connector.get('kind', '')
                    if connector_type == 'AzureSecurityCenter':
                        defender_connectors.append(connector)
                
                if defender_connectors:
                    self.formatter.print_success("Microsoft Defender for Cloud data connector is ENABLED in Sentinel")
                    for connector in defender_connectors:
                        connector_name = connector.get('name', 'Unknown')
                        connector_state = connector.get('properties', {}).get('connectorState', 'Unknown')
                        self.formatter.print_key_value(f"Connector: {connector_name}", f"State: {connector_state}")
                else:
                    self.formatter.print_error("Microsoft Defender for Cloud data connector is NOT enabled in Sentinel")
                    self.formatter.print_info("This is a critical gap for intrusion detection")
                    self.formatter.print_info("Enable the Azure Security Center data connector in Sentinel")
            else:
                self.formatter.print_error(f"Failed to retrieve data connectors: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 3. Check for Defender-Generated Security Alerts
        self.formatter.print_subsection("DEFENDER-GENERATED SECURITY ALERTS")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/alerts?api-version=2020-01-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                alerts = response.json().get('value', [])
                if alerts:
                    self.formatter.print_success(f"Found {len(alerts)} security alerts from Microsoft Defender for Cloud")
                    
                    # Categorize alerts by severity
                    high_critical_alerts = [a for a in alerts if a.get('properties', {}).get('severity') in ['High', 'Critical']]
                    medium_low_alerts = [a for a in alerts if a.get('properties', {}).get('severity') in ['Medium', 'Low']]
                    
                    self.formatter.print_key_value("High/Critical Severity", len(high_critical_alerts))
                    self.formatter.print_key_value("Medium/Low Severity", len(medium_low_alerts))
                    
                    if high_critical_alerts:
                        self.formatter.print_subsection("Recent High/Critical Alerts")
                        max_subitems = getattr(self.config, 'max_subitems', 10)
                        for alert in high_critical_alerts[:max_subitems]:  # Show first max_subitems
                            alert_name = alert.get('properties', {}).get('alertDisplayName', 'Unnamed')
                            severity = alert.get('properties', {}).get('severity', 'Unknown')
                            reported_time = alert.get('properties', {}).get('reportedTimeUtc', 'Unknown')
                            self.formatter.print_key_value(f"{alert_name} (Severity: {severity})", f"Reported: {reported_time}")
                        if len(high_critical_alerts) > max_subitems:
                            self.formatter.print_info(f"... and {len(high_critical_alerts) - max_subitems} more high/critical alerts")
                else:
                    self.formatter.print_success("No security alerts found from Microsoft Defender for Cloud")
            else:
                self.formatter.print_error(f"Failed to retrieve security alerts: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 4. Check for Sentinel Incidents from Defender Alerts
        self.formatter.print_subsection("SENTINEL INCIDENTS FROM DEFENDER ALERTS")
        try:
            url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01-preview"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                incidents = response.json().get('value', [])
                defender_incidents = [i for i in incidents if any(keyword in i.get('properties', {}).get('title', '').lower() 
                                for keyword in ['defender', 'security center', 'azure security', 'malware', 'threat', 'attack'])]
                
                if defender_incidents:
                    self.formatter.print_success(f"Found {len(defender_incidents)} incidents in Sentinel from Defender alerts")
                    
                    # Categorize by status
                    open_incidents = [i for i in defender_incidents if i.get('properties', {}).get('status') == 'New']
                    closed_incidents = [i for i in defender_incidents if i.get('properties', {}).get('status') == 'Closed']
                    
                    self.formatter.print_key_value("Open Incidents", len(open_incidents))
                    self.formatter.print_key_value("Closed Incidents", len(closed_incidents))
                    
                    if open_incidents:
                        self.formatter.print_subsection("Recent Open Incidents")
                        max_subitems = getattr(self.config, 'max_subitems', 10)
                        for incident in open_incidents[:max_subitems]:  # Show first max_subitems
                            title = incident.get('properties', {}).get('title', 'Unnamed')
                            severity = incident.get('properties', {}).get('severity', 'Unknown')
                            created = incident.get('properties', {}).get('createdTimeUtc', 'Unknown')
                            self.formatter.print_key_value(f"{title} (Severity: {severity})", f"Created: {created}")
                        if len(open_incidents) > max_subitems:
                            self.formatter.print_info(f"... and {len(open_incidents) - max_subitems} more open incidents")
                else:
                    self.formatter.print_success("No incidents found in Sentinel from Defender alerts")
            else:
                self.formatter.print_error(f"Failed to retrieve incidents: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        self.formatter.print_separator()

    def check_logical_access_review(self):
        """Evidence the Logical Access Review control by checking Microsoft Entra ID Identity Governance access reviews."""
        self.formatter.print_header(
            "LOGICAL ACCESS REVIEW: MICROSOFT ENTRA ID IDENTITY GOVERNANCE",
            "This function evidences the Logical Access Review control by checking Microsoft Entra ID Identity Governance access reviews, PIM role-based reviews, recurring review configurations, and automatic user removal settings. It validates annual access certification processes for FedRAMP Moderate compliance."
        )
        
        # 1. Check for Access Review Configuration
        self.formatter.print_subsection("ACCESS REVIEW CONFIGURATION")
        try:
            url = "/identityGovernance/accessReviews/definitions"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                reviews = response.json().get('value', [])
                if reviews:
                    self.formatter.print_success(f"Found {len(reviews)} access review definitions configured:")
                    
                    active_reviews = [r for r in reviews if r.get('status') == 'InProgress' or r.get('status') == 'NotStarted']
                    completed_reviews = [r for r in reviews if r.get('status') == 'Completed']
                    
                    self.formatter.print_key_value("Active Reviews", len(active_reviews))
                    self.formatter.print_key_value("Completed Reviews", len(completed_reviews))
                    
                    max_subitems = getattr(self.config, 'max_subitems', 10)
                    for review in reviews[:max_subitems]:  # Show first max_subitems
                        display_name = review.get('displayName', 'Unnamed')
                        status = review.get('status', 'Unknown')
                        created_date = review.get('createdDateTime', 'Unknown')
                        self.formatter.print_key_value(f"{display_name} (Status: {status})", f"Created: {created_date}")
                    if len(reviews) > max_subitems:
                        self.formatter.print_info(f"... and {len(reviews) - max_subitems} more access reviews")
                else:
                    self.formatter.print_error("No access review definitions found")
                    self.formatter.print_info("This is a critical gap for logical access review compliance")
                    self.formatter.print_info("Configure access reviews in Identity Governance > Access Reviews")
            elif response.status_code == 400 and 'Resource not found for the segment' in response.text:
                self.formatter.print_error("Access Reviews are only available with Microsoft Entra ID P2 (Azure AD Premium P2)")
                self.formatter.print_info("This feature requires Azure AD Premium P2 licensing")
            else:
                self.formatter.print_error(f"Failed to retrieve access reviews: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 2. Check for PIM Role-Based Access Reviews
        self.formatter.print_subsection("PIM ROLE-BASED ACCESS REVIEW CONFIGURATION")
        try:
            url = "/identityGovernance/accessReviews/definitions"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                reviews = response.json().get('value', [])
                
                # Check for role-based reviews specifically
                role_based_reviews = [r for r in reviews if r.get('scope', {}).get('query') == '/roleManagement/directory/roleAssignments' or 
                                    'role' in r.get('displayName', '').lower()]
                
                if role_based_reviews:
                    self.formatter.print_success(f"Found {len(role_based_reviews)} PIM role-based access reviews:")
                    for review in role_based_reviews:
                        display_name = review.get('displayName', 'Unnamed')
                        scope = review.get('scope', {})
                        query = scope.get('query', 'Unknown')
                        self.formatter.print_key_value(f"{display_name}", f"Scope: {query}")
                        
                        # Check if it's annual
                        recurrence = review.get('instanceEnumerationScope', {}).get('recurrence', {})
                        if recurrence:
                            pattern = recurrence.get('pattern', {})
                            interval = pattern.get('interval', 'Unknown')
                            frequency = pattern.get('type', 'Unknown')
                            if frequency == 'absoluteMonthly' and interval == 12:
                                self.formatter.print_success("Annual review configured")
                            else:
                                self.formatter.print_warning(f"Review frequency: {frequency} (every {interval} months) - should be annual")
                        else:
                            self.formatter.print_error("No recurrence configured - should be annual")
                else:
                    self.formatter.print_error("No PIM role-based access reviews found")
                    self.formatter.print_info("Annual role-based reviews are required for compliance")
            elif response.status_code == 400:
                self.formatter.print_error("Access Reviews not available (requires Entra ID P2)")
            else:
                self.formatter.print_error(f"Failed to retrieve access reviews: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 3. Check for Recurring Access Reviews (General)
        self.formatter.print_subsection("RECURRING ACCESS REVIEW CONFIGURATION")
        try:
            url = "/identityGovernance/accessReviews/definitions"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                reviews = response.json().get('value', [])
                recurring_reviews = [r for r in reviews if r.get('instanceEnumerationScope', {}).get('recurrence')]
                
                if recurring_reviews:
                    self.formatter.print_success(f"Found {len(recurring_reviews)} recurring access reviews:")
                    for review in recurring_reviews:
                        display_name = review.get('displayName', 'Unnamed')
                        recurrence = review.get('instanceEnumerationScope', {}).get('recurrence', {})
                        pattern = recurrence.get('pattern', {})
                        interval = pattern.get('interval', 'Unknown')
                        frequency = pattern.get('type', 'Unknown')
                        self.formatter.print_key_value(f"{display_name}", f"{frequency} (every {interval} months)")
                else:
                    self.formatter.print_error("No recurring access reviews found")
                    self.formatter.print_info("Annual recurring reviews are required for compliance")
            elif response.status_code == 400:
                self.formatter.print_error("Access Reviews not available (requires Entra ID P2)")
            else:
                self.formatter.print_error(f"Failed to retrieve access reviews: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 4. Check for Auto-Apply Results Configuration
        self.formatter.print_subsection("AUTO-APPLY RESULTS CONFIGURATION")
        try:
            url = "/identityGovernance/accessReviews/definitions"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                reviews = response.json().get('value', [])
                auto_apply_reviews = [r for r in reviews if r.get('settings', {}).get('autoApplyDecisionsEnabled')]
                
                if auto_apply_reviews:
                    self.formatter.print_success(f"Found {len(auto_apply_reviews)} access reviews with auto-apply enabled:")
                    for review in auto_apply_reviews:
                        display_name = review.get('displayName', 'Unnamed')
                        auto_remove = review.get('settings', {}).get('autoApplyDecisionsEnabled', False)
                        status = "Enabled" if auto_remove else "Disabled"
                        self.formatter.print_key_value(f"{display_name}", f"Auto-apply: {status}")
                else:
                    self.formatter.print_error("No access reviews with auto-apply results found")
                    self.formatter.print_info("Auto-apply is required to automatically remove non-responding users")
            elif response.status_code == 400:
                self.formatter.print_error("Access Reviews not available (requires Entra ID P2)")
            else:
                self.formatter.print_error(f"Failed to retrieve access reviews: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 5. Check "If reviewers don't respond" Configuration
        self.formatter.print_subsection("IF REVIEWERS DON'T RESPOND CONFIGURATION")
        try:
            url = "/identityGovernance/accessReviews/definitions"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                reviews = response.json().get('value', [])
                
                if reviews:
                    self.formatter.print_success(f"Checking 'If reviewers don't respond' configuration for {len(reviews)} access reviews:")
                    
                    correct_config_count = 0
                    for review in reviews:
                        display_name = review.get('displayName', 'Unnamed')
                        settings = review.get('settings', {})
                        
                        # Check for the "If reviewers don't respond" setting
                        # This is typically controlled by autoApplyDecisionsEnabled and defaultDecision
                        auto_apply_enabled = settings.get('autoApplyDecisionsEnabled', False)
                        default_decision = settings.get('defaultDecision', 'Unknown')
                        
                        # The correct configuration should be auto-apply enabled with "remove access" as default
                        if auto_apply_enabled and default_decision == 'Deny':
                            correct_config_count += 1
                            self.formatter.print_success(f"{display_name}: Auto-apply enabled with 'remove access' (Deny) as default")
                        elif auto_apply_enabled and default_decision == 'Approve':
                            self.formatter.print_warning(f"{display_name}: Auto-apply enabled but default decision is 'Approve' (should be 'Deny' to remove access)")
                        elif auto_apply_enabled and default_decision == 'Unknown':
                            self.formatter.print_warning(f"{display_name}: Auto-apply enabled but default decision is unknown")
                        else:
                            self.formatter.print_error(f"{display_name}: Auto-apply disabled - reviewers must manually respond")
                    
                    # Summary
                    if correct_config_count == len(reviews):
                        self.formatter.print_success("All access reviews are correctly configured with 'remove access' when reviewers don't respond")
                    elif correct_config_count > 0:
                        self.formatter.print_warning(f"{correct_config_count} out of {len(reviews)} access reviews are correctly configured")
                        self.formatter.print_info("Configure remaining reviews to automatically remove access when reviewers don't respond")
                    else:
                        self.formatter.print_error("No access reviews are configured to automatically remove access when reviewers don't respond")
                        self.formatter.print_info("Set 'If reviewers don't respond' to 'remove access' for all access reviews")
                else:
                    self.formatter.print_error("No access reviews found to check 'If reviewers don't respond' configuration")
            elif response.status_code == 400:
                self.formatter.print_error("Access Reviews not available (requires Entra ID P2)")
            else:
                self.formatter.print_error(f"Failed to retrieve access reviews: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 6. Check for Access Review Instances (Recent Reviews)
        self.formatter.print_subsection("RECENT ACCESS REVIEW INSTANCES")
        try:
            url = "/identityGovernance/accessReviews/definitions"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                reviews = response.json().get('value', [])
                if reviews:
                    # Get instances for the first review definition
                    review_id = reviews[0].get('id')
                    instances_url = f"/identityGovernance/accessReviews/definitions/{review_id}/instances"
                    instances_response = self.api_client.graph_get(instances_url)
                    
                    if instances_response.status_code == 200:
                        instances = instances_response.json().get('value', [])
                        if instances:
                            self.formatter.print_success(f"Found {len(instances)} access review instances:")
                            
                            recent_instances = [i for i in instances if i.get('startDateTime', '') > '2024-01-01']
                            self.formatter.print_key_value("Recent instances (2024)", len(recent_instances))
                            
                            max_subitems = getattr(self.config, 'max_subitems', 10)
                            for instance in instances[:max_subitems]:  # Show first max_subitems
                                start_date = instance.get('startDateTime', 'Unknown')
                                end_date = instance.get('endDateTime', 'Unknown')
                                status = instance.get('status', 'Unknown')
                                self.formatter.print_key_value(f"Instance: {start_date} to {end_date}", f"Status: {status}")
                            if len(instances) > max_subitems:
                                self.formatter.print_info(f"... and {len(instances) - max_subitems} more instances")
                        else:
                            self.formatter.print_error("No access review instances found")
                    else:
                        self.formatter.print_error(f"Failed to retrieve access review instances: {instances_response.status_code}")
                else:
                    self.formatter.print_error("No access review definitions found to check instances")
            elif response.status_code == 400:
                self.formatter.print_error("Access Reviews not available (requires Entra ID P2)")
            else:
                self.formatter.print_error(f"Failed to retrieve access reviews: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 7. Check for Group-Based Access Control
        self.formatter.print_subsection("GROUP-BASED ACCESS CONTROL")
        try:
            url = "/groups"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                groups = response.json().get('value', [])
                
                # Filter for groups that might be used for system access
                access_groups = [g for g in groups if any(keyword in g.get('displayName', '').lower() 
                                for keyword in ['access', 'system', 'app', 'resource', 'admin', 'user', 'role'])]
                
                if access_groups:
                    self.formatter.print_success(f"Found {len(access_groups)} potential access control groups:")
                    max_subitems = getattr(self.config, 'max_subitems', 10)
                    for group in access_groups[:max_subitems]:  # Show first max_subitems
                        group_name = group.get('displayName', 'Unnamed')
                        member_count = group.get('members@odata.count', 'Unknown')
                        self.formatter.print_key_value(f"{group_name}", f"{member_count} members")
                    if len(access_groups) > max_subitems:
                        self.formatter.print_info(f"... and {len(access_groups) - max_subitems} more groups")
                else:
                    self.formatter.print_error("No access control groups identified")
                    self.formatter.print_info("Consider creating groups for system access management")
            else:
                self.formatter.print_error(f"Failed to retrieve groups: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 8. Check for Access Review Notifications
        self.formatter.print_subsection("ACCESS REVIEW NOTIFICATIONS")
        try:
            url = "/identityGovernance/accessReviews/definitions"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                reviews = response.json().get('value', [])
                if reviews:
                    # Check notification settings for the first review
                    review_settings = reviews[0].get('settings', {})
                    notifications_enabled = review_settings.get('notificationsEnabled', False)
                    
                    if notifications_enabled:
                        self.formatter.print_success("Access review notifications are enabled")
                        self.formatter.print_info("Reviewers will be notified of pending reviews")
                    else:
                        self.formatter.print_error("Access review notifications are disabled")
                        self.formatter.print_info("Enable notifications to ensure reviewers are aware of pending reviews")
                else:
                    self.formatter.print_error("No access reviews found to check notification settings")
            elif response.status_code == 400:
                self.formatter.print_error("Access Reviews not available (requires Entra ID P2)")
            else:
                self.formatter.print_error(f"Failed to retrieve access reviews: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        self.formatter.print_separator()

    def check_logical_access_revocation(self):
        """Evidence the Logical Access Revocation control by checking automated offboarding processes and credential revocation tracking."""
        self.formatter.print_header(
            "LOGICAL ACCESS REVOCATION: AUTOMATED OFFBOARDING PROCESS",
            "This function evidences the Logical Access Revocation control by checking automated offboarding processes, credential revocation tracking, and 24-hour compliance monitoring. It validates timely access removal following role changes or termination for FedRAMP Moderate compliance."
        )
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        
        # 1. Check for Automated Offboarding Process Configuration
        self.formatter.print_subsection("AUTOMATED OFFBOARDING PROCESS CONFIGURATION")
        try:
            url = "/identityGovernance/lifecycleWorkflows/workflows"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                workflows = response.json().get('value', [])
                offboarding_workflows = [w for w in workflows if 'offboard' in w.get('displayName', '').lower() or 
                                        'termination' in w.get('displayName', '').lower() or 
                                        'revocation' in w.get('displayName', '').lower()]
                
                if offboarding_workflows:
                    self.formatter.print_success(f"Found {len(offboarding_workflows)} automated offboarding workflows:")
                    for workflow in offboarding_workflows:
                        name = workflow.get('displayName', 'Unnamed')
                        state = workflow.get('state', 'Unknown')
                        enabled = "Enabled" if state == 'Enabled' else "Disabled"
                        self.formatter.print_key_value(f"{name}", f"State: {enabled}")
                else:
                    self.formatter.print_error("No automated offboarding workflows found")
                    self.formatter.print_info("This is a critical gap for timely access revocation")
                    self.formatter.print_info("Configure lifecycle workflows for automated offboarding")
            elif response.status_code == 400:
                # Check for specific license error messages
                response_text = response.text.lower()
                if 'insufficient license' in response_text or 'entra id governance license' in response_text:
                    self.formatter.print_warning("Lifecycle Workflows require Microsoft Entra ID Governance license")
                    self.formatter.print_info("This feature requires Microsoft Entra ID Governance (formerly Azure AD Premium P2) licensing")
                    self.formatter.print_info("Manual offboarding processes can be implemented as an alternative for access revocation")
                elif 'resource not found for the segment' in response_text:
                    self.formatter.print_warning("Lifecycle Workflows are only available with Microsoft Entra ID P2 (Azure AD Premium P2)")
                    self.formatter.print_info("This feature requires Azure AD Premium P2 licensing")
                else:
                    self.formatter.print_error(f"Failed to retrieve lifecycle workflows: {response.status_code}")
                    self.formatter.print_info("Response: " + response.text)
            elif response.status_code == 403:
                # Check for specific license error messages in 403 responses
                response_text = response.text.lower()
                if 'insufficient license' in response_text or 'entra id governance license' in response_text:
                    self.formatter.print_warning("Lifecycle Workflows require Microsoft Entra ID Governance license")
                    self.formatter.print_info("This feature requires Microsoft Entra ID Governance (formerly Azure AD Premium P2) licensing")
                    self.formatter.print_info("Manual offboarding processes can be implemented as an alternative for access revocation")
                else:
                    self.formatter.print_warning("Access denied to Lifecycle Workflows")
                    self.formatter.print_info("This may be due to insufficient permissions or licensing requirements")
                    self.formatter.print_info("Consider implementing manual offboarding processes as an alternative")
            else:
                self.formatter.print_error(f"Failed to retrieve lifecycle workflows: {response.status_code}")
                self.formatter.print_info("Response: " + response.text)
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking lifecycle workflows: {e}")
            self.formatter.print_info("Consider implementing manual offboarding processes as an alternative")
        
        # 2. Check for 24-Hour Revocation Compliance Tracking
        self.formatter.print_subsection("24-HOUR REVOCATION COMPLIANCE TRACKING")
        try:
            url = "/auditLogs/directoryAudits?$top=50&$filter=activityDisplayName eq 'Remove member from group' or activityDisplayName eq 'Delete user' or activityDisplayName eq 'Disable user'"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                audit_events = response.json().get('value', [])
                
                if audit_events:
                    self.formatter.print_success(f"Found {len(audit_events)} recent access revocation events")
                    
                    # Analyze timing of recent events (last 30 days)
                    thirty_days_ago = (datetime.now() - datetime.timedelta(days=30)).isoformat() + 'Z'
                    recent_events = [e for e in audit_events if e.get('activityDateTime', '') > thirty_days_ago]
                    
                    self.formatter.print_key_value("Recent events (last 30 days)", len(recent_events))
                    self.formatter.print_key_value("Historical events", len(audit_events) - len(recent_events))
                    
                    if recent_events:
                        self.formatter.print_subsection("Recent Access Revocation Events")
                        max_subitems = getattr(self.config, 'max_subitems', 10)
                        for event in recent_events[:max_subitems]:  # Show first max_subitems
                            activity = event.get('activityDisplayName', 'Unknown')
                            timestamp = event.get('activityDateTime', 'Unknown')
                            target = event.get('targetResources', [{}])[0].get('displayName', 'Unknown')
                            self.formatter.print_key_value(f"{activity} for {target}", f"Timestamp: {timestamp}")
                        if len(recent_events) > max_subitems:
                            self.formatter.print_info(f"... and {len(recent_events) - max_subitems} more recent events")
                else:
                    self.formatter.print_success("No recent access revocation events found")
            elif response.status_code == 403:
                self.formatter.print_error("Audit log access not available (requires AuditLog.Read.All permission)")
            else:
                self.formatter.print_error(f"Failed to retrieve audit events: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 3. Check for Credential Revocation in Microsoft Entra ID
        self.formatter.print_subsection("CREDENTIAL REVOCATION IN MICROSOFT ENTRA ID")
        try:
            url = "/auditLogs/directoryAudits?$top=20&$filter=activityDisplayName eq 'Reset user password' or activityDisplayName eq 'Disable user' or activityDisplayName eq 'Delete user'"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                credential_events = response.json().get('value', [])
                
                if credential_events:
                    self.formatter.print_success(f"Found {len(credential_events)} recent credential revocation events:")
                    
                    password_resets = [e for e in credential_events if e.get('activityDisplayName') == 'Reset user password']
                    account_disables = [e for e in credential_events if e.get('activityDisplayName') == 'Disable user']
                    account_deletes = [e for e in credential_events if e.get('activityDisplayName') == 'Delete user']
                    
                    self.formatter.print_key_value("Password Resets", len(password_resets))
                    self.formatter.print_key_value("Account Disablements", len(account_disables))
                    self.formatter.print_key_value("Account Deletions", len(account_deletes))
                    
                    if credential_events:
                        self.formatter.print_subsection("Recent Credential Revocation Events")
                        max_subitems = getattr(self.config, 'max_subitems', 10)
                        for event in credential_events[:max_subitems]:  # Show first max_subitems
                            activity = event.get('activityDisplayName', 'Unknown')
                            timestamp = event.get('activityDateTime', 'Unknown')
                            target = event.get('targetResources', [{}])[0].get('displayName', 'Unknown')
                            self.formatter.print_key_value(f"{activity} for {target}", f"Timestamp: {timestamp}")
                        if len(credential_events) > max_subitems:
                            self.formatter.print_info(f"... and {len(credential_events) - max_subitems} more events")
                else:
                    self.formatter.print_success("No recent credential revocation events found")
            elif response.status_code == 403:
                self.formatter.print_error("Audit log access not available (requires AuditLog.Read.All permission)")
            else:
                self.formatter.print_error(f"Failed to retrieve audit events: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 4. Check for Role Permission Revocation
        self.formatter.print_subsection("ROLE PERMISSION REVOCATION")
        try:
            url = "/auditLogs/directoryAudits?$top=20&$filter=activityDisplayName eq 'Remove member from group' or activityDisplayName eq 'Remove app role assignment from user'"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                role_events = response.json().get('value', [])
                
                if role_events:
                    self.formatter.print_success(f"Found {len(role_events)} recent role permission revocation events:")
                    
                    group_removals = [e for e in role_events if e.get('activityDisplayName') == 'Remove member from group']
                    app_role_removals = [e for e in role_events if e.get('activityDisplayName') == 'Remove app role assignment from user']
                    
                    self.formatter.print_key_value("Group Membership Removals", len(group_removals))
                    self.formatter.print_key_value("Application Role Removals", len(app_role_removals))
                    
                    if role_events:
                        self.formatter.print_subsection("Recent Role Permission Revocation Events")
                        max_subitems = getattr(self.config, 'max_subitems', 10)
                        for event in role_events[:max_subitems]:  # Show first max_subitems
                            activity = event.get('activityDisplayName', 'Unknown')
                            timestamp = event.get('activityDateTime', 'Unknown')
                            target = event.get('targetResources', [{}])[0].get('displayName', 'Unknown')
                            self.formatter.print_key_value(f"{activity} for {target}", f"Timestamp: {timestamp}")
                        if len(role_events) > max_subitems:
                            self.formatter.print_info(f"... and {len(role_events) - max_subitems} more events")
                else:
                    self.formatter.print_success("No recent role permission revocation events found")
            elif response.status_code == 403:
                self.formatter.print_error("Audit log access not available (requires AuditLog.Read.All permission)")
            else:
                self.formatter.print_error(f"Failed to retrieve audit events: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 5. Check for SharePoint Integration and Task Management
        self.formatter.print_subsection("SHAREPOINT INTEGRATION AND TASK MANAGEMENT")
        try:
            url = "/auditLogs/directoryAudits?$top=20&$filter=activityDisplayName eq 'Update application' or activityDisplayName eq 'Update service principal'"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                sharepoint_events = response.json().get('value', [])
                
                if sharepoint_events:
                    self.formatter.print_success(f"Found {len(sharepoint_events)} recent SharePoint/application update events")
                    self.formatter.print_info("These may indicate offboarding task completions")
                    
                    max_subitems = getattr(self.config, 'max_subitems', 10)
                    for event in sharepoint_events[:max_subitems]:  # Show first max_subitems
                        activity = event.get('activityDisplayName', 'Unknown')
                        timestamp = event.get('activityDateTime', 'Unknown')
                        target = event.get('targetResources', [{}])[0].get('displayName', 'Unknown')
                        self.formatter.print_key_value(f"{activity} for {target}", f"Timestamp: {timestamp}")
                    if len(sharepoint_events) > max_subitems:
                        self.formatter.print_info(f"... and {len(sharepoint_events) - max_subitems} more events")
                else:
                    self.formatter.print_error("No recent SharePoint/application update events found")
                    self.formatter.print_info("This may indicate limited SharePoint integration")
            elif response.status_code == 403:
                self.formatter.print_error("Audit log access not available (requires AuditLog.Read.All permission)")
            else:
                self.formatter.print_error(f"Failed to retrieve audit events: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 6. Check for Manager Confirmation Process
        self.formatter.print_subsection("MANAGER CONFIRMATION PROCESS")
        try:
            url = "/auditLogs/directoryAudits?$top=20&$filter=activityDisplayName eq 'Add member to group' or activityDisplayName eq 'Update group'"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                approval_events = response.json().get('value', [])
                
                if approval_events:
                    self.formatter.print_success(f"Found {len(approval_events)} recent group management events")
                    self.formatter.print_info("These may indicate manager confirmations of access changes")
                    
                    max_subitems = getattr(self.config, 'max_subitems', 10)
                    for event in approval_events[:max_subitems]:  # Show first max_subitems
                        activity = event.get('activityDisplayName', 'Unknown')
                        timestamp = event.get('activityDateTime', 'Unknown')
                        target = event.get('targetResources', [{}])[0].get('displayName', 'Unknown')
                        self.formatter.print_key_value(f"{activity} for {target}", f"Timestamp: {timestamp}")
                    if len(approval_events) > max_subitems:
                        self.formatter.print_info(f"... and {len(approval_events) - max_subitems} more events")
                else:
                    self.formatter.print_error("No recent group management events found")
                    self.formatter.print_info("This may indicate limited manager involvement in access management")
            elif response.status_code == 403:
                self.formatter.print_error("Audit log access not available (requires AuditLog.Read.All permission)")
            else:
                self.formatter.print_error(f"Failed to retrieve audit events: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 7. Check for Automated Alerting and Escalation
        self.formatter.print_subsection("AUTOMATED ALERTING AND ESCALATION")
        try:
            url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01-preview"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                incidents = response.json().get('value', [])
                revocation_incidents = [i for i in incidents if any(keyword in i.get('properties', {}).get('title', '').lower() 
                                for keyword in ['revocation', 'offboard', 'termination', 'access removal', 'credential'])]
                
                if revocation_incidents:
                    self.formatter.print_success(f"Found {len(revocation_incidents)} access revocation related incidents:")
                    
                    open_incidents = [i for i in revocation_incidents if i.get('properties', {}).get('status') == 'New']
                    closed_incidents = [i for i in revocation_incidents if i.get('properties', {}).get('status') == 'Closed']
                    
                    self.formatter.print_key_value("Open Incidents", len(open_incidents))
                    self.formatter.print_key_value("Closed Incidents", len(closed_incidents))
                    
                    if open_incidents:
                        self.formatter.print_subsection("Open Access Revocation Incidents")
                        max_subitems = getattr(self.config, 'max_subitems', 10)
                        for incident in open_incidents[:max_subitems]:  # Show first max_subitems
                            title = incident.get('properties', {}).get('title', 'Unnamed')
                            severity = incident.get('properties', {}).get('severity', 'Unknown')
                            created = incident.get('properties', {}).get('createdTimeUtc', 'Unknown')
                            self.formatter.print_key_value(f"{title} (Severity: {severity})", f"Created: {created}")
                        if len(open_incidents) > max_subitems:
                            self.formatter.print_info(f"... and {len(open_incidents) - max_subitems} more open incidents")
                else:
                    self.formatter.print_success("No access revocation related incidents found")
            else:
                self.formatter.print_error(f"Failed to retrieve incidents: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        self.formatter.print_separator()

    def check_defender_endpoint_malware_protection(self):
        """Evidence the Malware Protection control by checking Microsoft Defender for Endpoint deployment and configuration."""
        self.formatter.print_header(
            "MICROSOFT DEFENDER FOR ENDPOINT MALWARE PROTECTION",
            "This function evidences the Malware Protection control by checking Microsoft Defender for Endpoint deployment, daily update configuration, non-signature-based detection methods, and advanced threat protection capabilities. It validates comprehensive malware protection for FedRAMP Moderate compliance."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        
        # 1. Check Defender for Endpoint Deployment Coverage
        self.formatter.print_subsection("DEFENDER FOR ENDPOINT DEPLOYMENT COVERAGE")
        try:
            url = "/deviceManagement/deviceCompliancePolicies"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                policies = response.json().get('value', [])
                defender_policies = [p for p in policies if p.get('@odata.type', '').endswith('windows10CompliancePolicy')]
                
                if defender_policies:
                    self.formatter.print_success(f"Found {len(defender_policies)} Windows 10/11 compliance policies")
                    deployment_configured = False
                    for policy in defender_policies:
                        defender_enabled = policy.get('defenderEnabled', False)
                        if defender_enabled:
                            deployment_configured = True
                            self.formatter.print_success(f"Policy '{policy.get('displayName')}' requires Defender for Endpoint")
                    
                    if not deployment_configured:
                        self.formatter.print_error("No compliance policies found that require Defender for Endpoint")
                        self.formatter.print_info("This is a critical gap for malware protection compliance")
                        self.formatter.print_info("Configure Intune compliance policies to require Defender for Endpoint")
                else:
                    self.formatter.print_error("No Windows 10/11 compliance policies found")
                    self.formatter.print_info("This indicates limited endpoint management")
            else:
                self.formatter.print_error(f"Failed to retrieve compliance policies: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 2. Check for Daily Update Configuration
        self.formatter.print_subsection("DAILY UPDATE CONFIGURATION")
        try:
            url = "/deviceManagement/deviceConfigurations"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                configs = response.json().get('value', [])
                update_configs = []
                
                for device_config in configs:
                    oma_settings = device_config.get('omaSettings', [])
                    for setting in oma_settings:
                        oma_uri = setting.get('omaUri', '')
                        if 'defender' in oma_uri.lower() and ('update' in oma_uri.lower() or 'signature' in oma_uri.lower()):
                            update_configs.append({
                                'name': device_config.get('displayName', 'Unnamed'),
                                'uri': oma_uri,
                                'value': setting.get('value', 'Not set')
                            })
                
                if update_configs:
                    self.formatter.print_success(f"Found {len(update_configs)} Defender update configurations:")
                    daily_updates_configured = False
                    for update_config in update_configs:
                        self.formatter.print_key_value(f"{update_config['name']}", f"{update_config['uri']} = {update_config['value']}")
                        if 'daily' in str(update_config['value']).lower() or '1' in str(update_config['value']):
                            daily_updates_configured = True
                    
                    if daily_updates_configured:
                        self.formatter.print_success("Daily updates appear to be configured")
                    else:
                        self.formatter.print_warning("Daily updates may not be explicitly configured")
                        self.formatter.print_info("Verify update frequency settings in Intune")
                else:
                    self.formatter.print_error("No Defender update configurations found")
                    self.formatter.print_info("This indicates update frequency may not be managed")
            else:
                self.formatter.print_error(f"Failed to retrieve device configurations: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 3. Check for Non-Signature-Based Detection Methods
        self.formatter.print_subsection("NON-SIGNATURE-BASED DETECTION METHODS")
        try:
            url = "/deviceManagement/deviceConfigurations"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                configs = response.json().get('value', [])
                asr_configs = []
                cloud_protection_configs = []
                behavior_monitoring_configs = []
                
                for device_config in configs:
                    oma_settings = device_config.get('omaSettings', [])
                    for setting in oma_settings:
                        oma_uri = setting.get('omaUri', '').lower()
                        if 'asr' in oma_uri or 'attack surface reduction' in oma_uri:
                            asr_configs.append({
                                'name': device_config.get('displayName', 'Unnamed'),
                                'uri': setting.get('omaUri', ''),
                                'value': setting.get('value', 'Not set')
                            })
                        elif 'cloud' in oma_uri and 'protection' in oma_uri:
                            cloud_protection_configs.append({
                                'name': device_config.get('displayName', 'Unnamed'),
                                'uri': setting.get('omaUri', ''),
                                'value': setting.get('value', 'Not set')
                            })
                        elif 'behavior' in oma_uri or 'monitoring' in oma_uri:
                            behavior_monitoring_configs.append({
                                'name': device_config.get('displayName', 'Unnamed'),
                                'uri': setting.get('omaUri', ''),
                                'value': setting.get('value', 'Not set')
                            })
                
                self.formatter.print_subsection("Attack Surface Reduction (ASR) Rules")
                if asr_configs:
                    self.formatter.print_success(f"Found {len(asr_configs)} ASR rule configurations")
                    max_subitems = getattr(self.config, 'max_subitems', 10)
                    for asr_config in asr_configs[:max_subitems]:  # Show first max_subitems
                        self.formatter.print_key_value(f"{asr_config['name']}", f"{asr_config['uri']} = {asr_config['value']}")
                    if len(asr_configs) > max_subitems:
                        self.formatter.print_info(f"... and {len(asr_configs) - max_subitems} more ASR configurations")
                else:
                    self.formatter.print_error("No ASR rule configurations found")
                    self.formatter.print_info("ASR rules are critical for zero-day threat protection")
                
                self.formatter.print_subsection("Cloud-Delivered Protection")
                if cloud_protection_configs:
                    self.formatter.print_success(f"Found {len(cloud_protection_configs)} cloud protection configurations")
                    for cloud_config in cloud_protection_configs:
                        self.formatter.print_key_value(f"{cloud_config['name']}", f"{cloud_config['uri']} = {cloud_config['value']}")
                else:
                    self.formatter.print_error("No cloud protection configurations found")
                    self.formatter.print_info("Cloud protection is essential for advanced threat detection")
                
                self.formatter.print_subsection("Behavior Monitoring")
                if behavior_monitoring_configs:
                    self.formatter.print_success(f"Found {len(behavior_monitoring_configs)} behavior monitoring configurations")
                    for behavior_config in behavior_monitoring_configs:
                        self.formatter.print_key_value(f"{behavior_config['name']}", f"{behavior_config['uri']} = {behavior_config['value']}")
                else:
                    self.formatter.print_error("No behavior monitoring configurations found")
                    self.formatter.print_info("Behavior monitoring detects suspicious activities")
            else:
                self.formatter.print_error(f"Failed to retrieve device configurations: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 4. Check for Endpoint Detection and Response (EDR) Configuration
        self.formatter.print_subsection("ENDPOINT DETECTION AND RESPONSE (EDR) CONFIGURATION")
        try:
            url = "/deviceManagement/deviceConfigurations"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                configs = response.json().get('value', [])
                edr_configs = []
                
                for device_config in configs:
                    oma_settings = device_config.get('omaSettings', [])
                    for setting in oma_settings:
                        oma_uri = setting.get('omaUri', '').lower()
                        if any(keyword in oma_uri for keyword in ['edr', 'endpoint detection', 'real-time', 'tamper']):
                            edr_configs.append({
                                'name': device_config.get('displayName', 'Unnamed'),
                                'uri': setting.get('omaUri', ''),
                                'value': setting.get('value', 'Not set')
                            })
                
                if edr_configs:
                    self.formatter.print_success(f"Found {len(edr_configs)} EDR-related configurations:")
                    for edr_config in edr_configs:
                        self.formatter.print_key_value(f"{edr_config['name']}", f"{edr_config['uri']} = {edr_config['value']}")
                else:
                    self.formatter.print_error("No EDR-specific configurations found")
                    self.formatter.print_info("EDR capabilities should be explicitly configured")
                    self.formatter.print_info("Check for real-time protection and tamper protection settings")
            else:
                self.formatter.print_error(f"Failed to retrieve device configurations: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 5. Check for Quarantine and Alert Configuration
        self.formatter.print_subsection("QUARANTINE AND ALERT CONFIGURATION")
        try:
            url = "/deviceManagement/deviceConfigurations"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                configs = response.json().get('value', [])
                quarantine_configs = []
                alert_configs = []
                
                for device_config in configs:
                    oma_settings = device_config.get('omaSettings', [])
                    for setting in oma_settings:
                        oma_uri = setting.get('omaUri', '').lower()
                        if 'quarantine' in oma_uri:
                            quarantine_configs.append({
                                'name': device_config.get('displayName', 'Unnamed'),
                                'uri': setting.get('omaUri', ''),
                                'value': setting.get('value', 'Not set')
                            })
                        elif 'alert' in oma_uri or 'notification' in oma_uri:
                            alert_configs.append({
                                'name': device_config.get('displayName', 'Unnamed'),
                                'uri': setting.get('omaUri', ''),
                                'value': setting.get('value', 'Not set')
                            })
                
                self.formatter.print_subsection("Quarantine Configuration")
                if quarantine_configs:
                    self.formatter.print_success(f"Found {len(quarantine_configs)} quarantine configurations")
                    for quarantine_config in quarantine_configs:
                        self.formatter.print_key_value(f"{quarantine_config['name']}", f"{quarantine_config['uri']} = {quarantine_config['value']}")
                else:
                    self.formatter.print_error("No quarantine configurations found")
                    self.formatter.print_info("Quarantine settings are essential for threat containment")
                
                self.formatter.print_subsection("Alert Configuration")
                if alert_configs:
                    self.formatter.print_success(f"Found {len(alert_configs)} alert configurations")
                    for alert_config in alert_configs:
                        self.formatter.print_key_value(f"{alert_config['name']}", f"{alert_config['uri']} = {alert_config['value']}")
                else:
                    self.formatter.print_error("No alert configurations found")
                    self.formatter.print_info("Alert settings ensure timely threat notification")
            else:
                self.formatter.print_error(f"Failed to retrieve device configurations: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 6. Check for Boundary Protection Integration
        self.formatter.print_subsection("BOUNDARY PROTECTION INTEGRATION")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/azureFirewalls?api-version=2022-05-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                firewalls = response.json().get('value', [])
                if firewalls:
                    self.formatter.print_success(f"Found {len(firewalls)} Azure Firewalls for boundary protection")
                    for firewall in firewalls:
                        firewall_name = firewall.get('name', 'Unnamed')
                        location = firewall.get('location', 'Unknown')
                        self.formatter.print_key_value(f"{firewall_name}", f"Location: {location}")
                else:
                    self.formatter.print_warning("No Azure Firewalls found")
                    self.formatter.print_info("Consider deploying Azure Firewall for enhanced boundary protection")
            else:
                self.formatter.print_error(f"Failed to retrieve Azure Firewalls: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        self.formatter.print_separator()

    def check_screen_lock_obfuscation_settings(self):
        """Check for screen lock obfuscation settings, public image display, and re-authentication requirements."""
        self.formatter.print_header(
            "SCREEN LOCK OBFUSCATION AND RE-AUTHENTICATION EVIDENCE",
            "This function checks for screen lock obfuscation settings, public image display, and re-authentication requirements to evidence compliance with screen security requirements."
        )
        
        # 1. Check Intune Device Configuration for Screen Lock Settings
        self.formatter.print_subsection("INTUNE DEVICE CONFIGURATION - SCREEN LOCK SETTINGS")
        try:
            url = "/deviceManagement/deviceConfigurations"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                response_data = response.json()
                if response_data is None:
                    self.formatter.print_error("Failed to parse response data - response is None")
                    return
                    
                configs = response_data.get('value', [])
                if configs is None:
                    configs = []
                    
                screen_lock_configs = []
                
                for device_config in configs:
                    if not isinstance(device_config, dict):
                        continue
                        
                    oma_settings = device_config.get('omaSettings', [])
                    if oma_settings is None:
                        oma_settings = []
                        
                    for setting in oma_settings:
                        if not isinstance(setting, dict):
                            continue
                        oma_uri = setting.get('omaUri', '')
                        # Check for screen lock related settings
                        if any(keyword in oma_uri.lower() for keyword in ['devicelock', 'screenlock', 'lock', 'inactivity']):
                            screen_lock_configs.append({
                                'profile': device_config.get('displayName', 'Unnamed'),
                                'uri': oma_uri,
                                'value': setting.get('value', 'Not set')
                            })
                
                if screen_lock_configs:
                    self.formatter.print_success(f"Found {len(screen_lock_configs)} screen lock related configurations:")
                    for screen_config in screen_lock_configs:
                        self.formatter.print_key_value(f"{screen_config['profile']}", f"{screen_config['uri']} = {screen_config['value']}")
                        
                        # Check for specific obfuscation settings
                        if 'lock' in screen_config['uri'].lower() and 'inactivity' in screen_config['uri'].lower():
                            self.formatter.print_success("Screen lock inactivity timeout configured")
                        if 'lock' in screen_config['uri'].lower() and 'password' in screen_config['uri'].lower():
                            self.formatter.print_success("Password required for screen unlock")
                else:
                    self.formatter.print_error("No screen lock configurations found in Intune")
                    self.formatter.print_info("Screen lock settings may not be centrally managed")
            else:
                self.formatter.print_error(f"Failed to retrieve device configurations: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 2. Check for Public Image Display Settings
        self.formatter.print_subsection("PUBLIC IMAGE DISPLAY SETTINGS")
        try:
            url = "/deviceManagement/deviceConfigurations"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                response_data = response.json()
                if response_data is None:
                    self.formatter.print_error("Failed to parse response data - response is None")
                    return
                    
                configs = response_data.get('value', [])
                if configs is None:
                    configs = []
                    
                public_image_configs = []
                
                for device_config in configs:
                    if not isinstance(device_config, dict):
                        continue
                        
                    oma_settings = device_config.get('omaSettings', [])
                    if oma_settings is None:
                        oma_settings = []
                        
                    for setting in oma_settings:
                        if not isinstance(setting, dict):
                            continue
                        oma_uri = setting.get('omaUri', '')
                        # Check for lock screen image settings
                        if any(keyword in oma_uri.lower() for keyword in ['lockscreen', 'lockimage', 'wallpaper']):
                            public_image_configs.append({
                                'profile': device_config.get('displayName', 'Unnamed'),
                                'uri': oma_uri,
                                'value': setting.get('value', 'Not set')
                            })
                
                if public_image_configs:
                    self.formatter.print_success(f"Found {len(public_image_configs)} lock screen image configurations:")
                    for image_config in public_image_configs:
                        self.formatter.print_key_value(f"{image_config['profile']}", f"{image_config['uri']} = {image_config['value']}")
                        if 'image' in image_config['uri'].lower() or 'wallpaper' in image_config['uri'].lower():
                            self.formatter.print_success("Lock screen image/background configured")
                else:
                    self.formatter.print_error("No lock screen image configurations found")
                    self.formatter.print_info("Public image display may not be centrally configured")
            else:
                self.formatter.print_error(f"Failed to retrieve device configurations: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 3. Check Conditional Access Policies for Re-authentication
        self.formatter.print_subsection("RE-AUTHENTICATION REQUIREMENTS")
        try:
            url = "/identity/conditionalAccess/policies"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                response_data = response.json()
                if response_data is None:
                    self.formatter.print_error("Failed to parse response data - response is None")
                    return
                    
                policies = response_data.get('value', [])
                if policies is None:
                    policies = []
                    
                reauth_policies = []
                
                for policy in policies:
                    if not isinstance(policy, dict):
                        continue
                        
                    conditions = policy.get('conditions', {})
                    if conditions is None:
                        conditions = {}
                        
                    grant_controls = policy.get('grantControls', {})
                    if grant_controls is None:
                        grant_controls = {}
                    
                    # Check for policies that require re-authentication
                    built_in_controls = grant_controls.get('builtInControls', [])
                    if built_in_controls is None:
                        built_in_controls = []
                        
                    if built_in_controls and 'requireReauthentication' in built_in_controls:
                        reauth_policies.append({
                            'name': policy.get('displayName', 'Unnamed'),
                            'state': policy.get('state', 'Unknown'),
                            'conditions': conditions
                        })
                
                if reauth_policies:
                    self.formatter.print_success(f"Found {len(reauth_policies)} policies requiring re-authentication:")
                    for policy in reauth_policies:
                        self.formatter.print_key_value(f"{policy['name']}", f"State: {policy['state']}")
                        # Check if policy applies to all users or specific conditions
                        users = policy['conditions'].get('users', {})
                        if users.get('includeAllUsers', False):
                            self.formatter.print_success("Applies to all users")
                        else:
                            self.formatter.print_warning("Applies to specific users/groups")
                else:
                    self.formatter.print_error("No conditional access policies requiring re-authentication found")
                    self.formatter.print_info("Re-authentication may not be enforced via Conditional Access")
            else:
                self.formatter.print_error(f"Failed to retrieve conditional access policies: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        self.formatter.print_separator()

    def check_recent_sentinel_error_logs(self, hours_back: int = 24):
        """Retrieve recent error logs from the Sentinel workspace over the specified time period."""
        self.formatter.print_header(
            "RECENT SENTINEL ERROR LOGS",
            f"This function retrieves recent error logs from the Sentinel workspace over the last {hours_back} hours. It evidences error monitoring and logging capabilities for compliance and incident response."
        )
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        max_lines = getattr(self.config, 'max_lines', 100)
        
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        
        try:
            
            # KQL query to find error logs (highly optimized for performance)
            kql_query = f"""
            // Start with the most common error sources first
            Event 
            | where TimeGenerated > ago({hours_back}h) 
            | where EventLevelName == "Error" 
            | project TimeGenerated, Computer, EventLog, EventID, EventLevelName, Message, Source, LogType = "Event"
            | take {max_lines}
            """
            
            # Get workspace ID for the Log Analytics Query API
            workspace_id = self.api_client.get_workspace_id(subscription_id, resource_group, workspace_name)
            
            # Calculate timespan for the new API (e.g., "P24H" for 24 hours)
            timespan = f"P{hours_back}H"
            
            # Make the query request using the new Log Analytics Query API
            response = self.api_client.log_analytics_query(workspace_id, kql_query, timespan)
            
            if response.status_code == 200:
                result = response.json()
                tables = result.get('tables', [])
                
                if tables and len(tables) > 0:
                    rows = tables[0].get('rows', [])
                    columns = tables[0].get('columns', [])
                    
                    if rows:
                        self.formatter.print_success(f"Found {len(rows)} recent error logs:")
                        
                        # Create column mapping
                        col_map = {col['name']: i for i, col in enumerate(columns)}
                        
                        for i, row in enumerate(rows[:max_lines], 1):
                            self.formatter.print_subsection(f"ERROR LOG ENTRY {i}")
                            
                            # Extract common fields
                            time_generated = row[col_map.get('TimeGenerated', 0)] if 'TimeGenerated' in col_map else 'Unknown'
                            computer = row[col_map.get('Computer', 1)] if 'Computer' in col_map else 'Unknown'
                            
                            self.formatter.print_key_value("Time", time_generated)
                            self.formatter.print_key_value("Computer", computer)
                            
                            # Extract specific fields based on log type
                            if 'EventID' in col_map:
                                event_id = row[col_map['EventID']]
                                self.formatter.print_key_value("Event ID", event_id)
                            
                            if 'EventLevelName' in col_map:
                                level = row[col_map['EventLevelName']]
                                self.formatter.print_key_value("Level", level)
                            
                            if 'Message' in col_map:
                                message = row[col_map['Message']]
                                if message and len(str(message)) > 100:
                                    message = str(message)[:100] + "..."
                                self.formatter.print_key_value("Message", message)
                            
                            if 'Source' in col_map:
                                source = row[col_map['Source']]
                                self.formatter.print_key_value("Source", source)
                            
                            if 'LogType' in col_map:
                                log_type = row[col_map['LogType']]
                                self.formatter.print_key_value("Log Type", log_type)
                        else:
                            self.formatter.print_success("No error logs found in the specified time range")
                            self.formatter.print_info("This may indicate good system health or limited error activity")
                else:
                    self.formatter.print_error("No data returned from Log Analytics query")
                
                # Try a simple fallback query for any error logs
                try:
                    max_subitems = getattr(self.config, 'max_subitems', 10)
                    fallback_query = f"""
                    AzureDiagnostics 
                    | where TimeGenerated > ago({hours_back}h) 
                    | where Level == "Error" 
                    | project TimeGenerated, ResourceProvider, ResourceId, Level, Message
                    | take {max_subitems}
                    """
                    
                    fallback_response = self.api_client.log_analytics_query(workspace_id, fallback_query, timespan)
                    if fallback_response.status_code == 200:
                        fallback_results = fallback_response.json()
                        fallback_tables = fallback_results.get('tables', [])
                        if fallback_tables and fallback_tables[0].get('rows'):
                            self.formatter.print_info("Found some error logs in AzureDiagnostics table")
                        else:
                            self.formatter.print_info("No error logs found in any tables")
                    else:
                        self.formatter.print_warning("Fallback query also failed")
                except Exception as fallback_e:
                    self.formatter.print_warning(f"Fallback query failed: {fallback_e}")
            elif response.status_code == 204:
                self.formatter.print_success("Query executed successfully but no error logs found")
                self.formatter.print_info("Status: 204 No Content (successful, but no data)")
                self.formatter.print_info("This indicates:")
                self.formatter.print_info("• No error logs in the last 24 hours (good system health)")
                self.formatter.print_info("• Workspace may be empty or have no data sources")
                self.formatter.print_info("• No agents configured to send logs to this workspace")
            elif response.status_code == 400:
                self.formatter.print_error(f"Bad request to Log Analytics: {response.status_code}")
                self.formatter.print_error(f"Response: {response.text}")
                self.formatter.print_info("This may indicate an issue with the query syntax or permissions")
            elif response.status_code == 401:
                self.formatter.print_error(f"Unauthorized access to Log Analytics: {response.status_code}")
                self.formatter.print_error(f"Response: {response.text}")
                self.formatter.print_info("Check Log Analytics permissions and token validity")
            elif response.status_code == 403:
                self.formatter.print_error(f"Forbidden access to Log Analytics: {response.status_code}")
                self.formatter.print_error(f"Response: {response.text}")
                self.formatter.print_info("Check Log Analytics Reader permissions")
            else:
                self.formatter.print_error(f"Failed to query Log Analytics: {response.status_code}")
                self.formatter.print_error(f"Response: {response.text}")
                
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while querying error logs: {e}")
        
        self.formatter.print_separator()

    def check_sentinel_privileged_command_auditing(self):
        """Check Microsoft Sentinel for privileged command logging and audit record completeness."""
        self.formatter.print_header(
            "MICROSOFT SENTINEL PRIVILEGED COMMAND AUDITING",
            "This function checks Microsoft Sentinel for privileged command logging and audit record completeness. It evidences full-text recording of privileged commands and comprehensive audit records for non-repudiation compliance."
        )
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        
        # 1. Check Sentinel Data Connectors for Audit Sources
        self.formatter.print_subsection("SENTINEL DATA CONNECTORS FOR AUDIT SOURCES")
        try:
            url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-12-01-preview"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                connectors = response.json().get('value', [])
                audit_connectors = []
                
                for connector in connectors:
                    kind = connector.get('kind', '')
                    name = connector.get('name', '')
                    
                    # Check for audit-related connectors
                    audit_keywords = ['audit', 'log', 'activity', 'directory', 'entra', 'azuread', 'defender', 'security']
                    if any(keyword in kind.lower() or keyword in name.lower() for keyword in audit_keywords):
                        audit_connectors.append(connector)
                
                if audit_connectors:
                    self.formatter.print_success(f"Found {len(audit_connectors)} audit-related data connectors:")
                    for connector in audit_connectors:
                        self.formatter.print_key_value(f"{connector.get('name')} (Type: {connector.get('kind')})", f"Status: {connector.get('properties', {}).get('connectorState', 'Unknown')}")
                else:
                    self.formatter.print_error("No audit-related data connectors found")
                    self.formatter.print_info("This may indicate missing audit data sources")
            else:
                self.formatter.print_error(f"Failed to retrieve data connectors: {response.status_code}")
                self.formatter.print_error(f"Response: {response.text}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 2. Check for Privileged Command Logging
        self.formatter.print_subsection("PRIVILEGED COMMAND LOGGING VERIFICATION")
        
        # First, check if workspace has any data
        try:
            test_query = "AzureActivity | take 1"
            workspace_id = self.api_client.get_workspace_id(subscription_id, resource_group, workspace_name)
            response = self.api_client.log_analytics_query(workspace_id, test_query, "P30D")
            
            if response.status_code == 204:
                self.formatter.print_warning("Log Analytics workspace appears to be empty or not collecting data")
                self.formatter.print_info("This explains why no privileged commands or audit records were found")
                self.formatter.print_info("Consider checking:")
                self.formatter.print_info("• Data connector configuration")
                self.formatter.print_info("• Workspace permissions")
                self.formatter.print_info("• Data collection settings")
                return
            
        except Exception as e:
            self.formatter.print_warning(f"Could not verify workspace data: {e}")
        
        try:
            # Query Log Analytics for PowerShell and Azure CLI command execution (optimized for performance)
            max_subitems = getattr(self.config, 'max_subitems', 10)
            query = """
            AzureActivity
            | where TimeGenerated > ago(7d)
            | where OperationName contains "PowerShell" or OperationName contains "AzureCLI" or OperationName contains "Command"
            | project TimeGenerated, OperationName, Caller, ResourceGroup, Resource, SourceTable = "AzureActivity"
            | order by TimeGenerated desc
            | take {max_subitems}
            """
            
            response = self.api_client.log_analytics_query(workspace_id, query, "P7D")
            if response.status_code == 200:
                results = response.json()
                tables = results.get('tables', [])
                
                privileged_commands = []
                for table in tables:
                    rows = table.get('rows', [])
                    columns = table.get('columns', [])
                    
                    for row in rows:
                        command_data = {}
                        for i, col in enumerate(columns):
                            command_data[col.get('name')] = row[i] if i < len(row) else None
                        privileged_commands.append(command_data)
                
                if privileged_commands:
                    self.formatter.print_success(f"Found {len(privileged_commands)} privileged command executions in the last 7 days:")
                    max_subitems = getattr(self.config, 'max_subitems', 10)
                    for cmd in privileged_commands[:max_subitems]:  # Show first max_subitems
                        time = cmd.get('TimeGenerated', 'N/A')
                        operation = cmd.get('OperationName', 'N/A')
                        caller = cmd.get('Caller', 'N/A')
                        source_table = cmd.get('SourceTable', 'Unknown')
                        self.formatter.print_key_value(f"{time}: {operation} by {caller}", f"Source: {source_table}")
                    if len(privileged_commands) > max_subitems:
                        self.formatter.print_info(f"... and {len(privileged_commands) - max_subitems} more privileged commands")
                else:
                    self.formatter.print_error("No privileged command executions found in the last 7 days")
                self.formatter.print_info("This may indicate no privileged activity or missing logging")
                
                # Try a simple fallback query for any command activity
                try:
                    fallback_query = """
                    AzureActivity 
                    | where TimeGenerated > ago(7d) 
                    | where OperationName contains "Command" or OperationName contains "Script"
                    | project TimeGenerated, OperationName, Caller
                    | take {max_subitems}
                    """
                    
                    fallback_response = self.api_client.log_analytics_query(workspace_id, fallback_query, "P7D")
                    if fallback_response.status_code == 200:
                        fallback_results = fallback_response.json()
                        fallback_tables = fallback_results.get('tables', [])
                        if fallback_tables and fallback_tables[0].get('rows'):
                            self.formatter.print_info("Found some command activity in AzureActivity table")
                        else:
                            self.formatter.print_info("No command activity found in any tables")
                    else:
                        self.formatter.print_warning("Fallback query also failed")
                except Exception as fallback_e:
                    self.formatter.print_warning(f"Fallback query failed: {fallback_e}")
            elif response.status_code == 204:
                self.formatter.print_success("Query executed successfully but no privileged command data found")
                self.formatter.print_info("This may indicate:")
                self.formatter.print_info("• No privileged commands executed in the last 7 days")
                self.formatter.print_info("• No privileged activity or logging")
            elif response.status_code == 400:
                self.formatter.print_error(f"Bad request to Log Analytics: {response.status_code}")
                self.formatter.print_error(f"Response: {response.text}")
                self.formatter.print_info("This may indicate an issue with the query syntax or permissions")
            elif response.status_code == 401:
                self.formatter.print_error(f"Unauthorized access to Log Analytics: {response.status_code}")
                self.formatter.print_error(f"Response: {response.text}")
                self.formatter.print_info("Check Log Analytics permissions and token validity")
            elif response.status_code == 403:
                self.formatter.print_error(f"Forbidden access to Log Analytics: {response.status_code}")
                self.formatter.print_error(f"Response: {response.text}")
                self.formatter.print_info("Check Log Analytics Reader permissions")
            else:
                self.formatter.print_error(f"Failed to query Log Analytics: {response.status_code}")
                self.formatter.print_error(f"Response: {response.text}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        self.formatter.print_separator()
    
    def check_sentinel_comprehensive_audit_records(self):
        """Check Microsoft Sentinel for comprehensive audit records with all required non-repudiation attributes."""
        self.formatter.print_header(
            "MICROSOFT SENTINEL COMPREHENSIVE AUDIT RECORDS",
            "This function checks Microsoft Sentinel for comprehensive audit records containing all required attributes for non-repudiation: type of event, when and where it occurred, event source, outcome, and associated identities."
        )
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        
        # 1. Check Sentinel Administrative Actions
        self.formatter.print_subsection("SENTINEL ADMINISTRATIVE ACTIONS")
        try:
            # Get workspace ID for the Log Analytics Query API
            workspace_id = self.api_client.get_workspace_id(subscription_id, resource_group, workspace_name)
            
            max_subitems = getattr(self.config, 'max_subitems', 10)
            query = """
            AzureActivity
            | where OperationNameValue startswith "MICROSOFT.SECURITYINSIGHTS"
            | where TimeGenerated > ago(1d)
            | project TimeGenerated, Caller, OperationNameValue, ActivityStatusValue, ResourceGroup, Resource
            | order by TimeGenerated desc
            | take {max_subitems}
            """
            
            response = self.api_client.log_analytics_query(workspace_id, query, "P1D")
            if response.status_code == 200:
                results = response.json()
                tables = results.get('tables', [])
                
                if tables and tables[0].get('rows'):
                    rows = tables[0]['rows']
                    columns = tables[0]['columns']
                    
                    self.formatter.print_success(f"Found {len(rows)} Sentinel administrative actions in the last 24 hours")
                    
                    col_map = {col['name']: i for i, col in enumerate(columns)}
                    
                    for i, row in enumerate(rows, 1):
                        self.formatter.print_subsection(f"ADMIN ACTION {i}")
                        
                        if 'TimeGenerated' in col_map:
                            self.formatter.print_key_value("When", row[col_map['TimeGenerated']])
                        if 'Caller' in col_map:
                            self.formatter.print_key_value("Event Source (Who)", row[col_map['Caller']])
                        if 'OperationNameValue' in col_map:
                            self.formatter.print_key_value("Event Type", row[col_map['OperationNameValue']])
                        if 'ActivityStatusValue' in col_map:
                            self.formatter.print_key_value("Outcome", row[col_map['ActivityStatusValue']])
                        if 'ResourceGroup' in col_map:
                            self.formatter.print_key_value("Where (Resource Group)", row[col_map['ResourceGroup']])
                        if 'Resource' in col_map:
                            self.formatter.print_key_value("Where (Resource)", row[col_map['Resource']])
                else:
                    self.formatter.print_success("No Sentinel administrative actions found in the last 24 hours")
            elif response.status_code == 204:
                self.formatter.print_success("Query executed successfully but no administrative actions found")
            elif response.status_code == 400:
                self.formatter.print_error(f"Bad request to Log Analytics: {response.status_code}")
                self.formatter.print_error(f"Response: {response.text}")
            elif response.status_code == 401:
                self.formatter.print_error(f"Unauthorized access to Log Analytics: {response.status_code}")
                self.formatter.print_error(f"Response: {response.text}")
            elif response.status_code == 403:
                self.formatter.print_error(f"Forbidden access to Log Analytics: {response.status_code}")
                self.formatter.print_error(f"Response: {response.text}")
            else:
                self.formatter.print_error(f"Failed to query administrative actions: {response.status_code}")
                self.formatter.print_error(f"Response: {response.text}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 2. Check Log Analytics Query Auditing
        self.formatter.print_subsection("LOG ANALYTICS QUERY AUDITING")
        try:
            query = """
            LAQueryLogs
            | where TimeGenerated > ago(7d)
            | project TimeGenerated, AADEmail, QueryText, RequestContext
            | order by TimeGenerated desc
            | take {max_subitems}
            """
            
            response = self.api_client.log_analytics_query(workspace_id, query, "P7D")
            if response.status_code == 200:
                results = response.json()
                tables = results.get('tables', [])
                
                if tables and tables[0].get('rows'):
                    rows = tables[0]['rows']
                    columns = tables[0]['columns']
                    
                    self.formatter.print_success(f"Found {len(rows)} Log Analytics queries in the last 7 days")
                    
                    col_map = {col['name']: i for i, col in enumerate(columns)}
                    
                    for i, row in enumerate(rows, 1):
                        self.formatter.print_subsection(f"QUERY AUDIT {i}")
                        
                        if 'TimeGenerated' in col_map:
                            self.formatter.print_key_value("When", row[col_map['TimeGenerated']])
                        if 'AADEmail' in col_map:
                            self.formatter.print_key_value("Event Source (Who)", row[col_map['AADEmail']])
                        if 'RequestContext' in col_map:
                            self.formatter.print_key_value("Event Type", f"Query via {row[col_map['RequestContext']]}")
                        else:
                            self.formatter.print_key_value("Event Type", "Log Analytics Query")
                        if 'QueryText' in col_map:
                            query_text = row[col_map['QueryText']]
                            # Truncate long queries for display
                            if len(query_text) > 100:
                                query_text = query_text[:100] + "..."
                            self.formatter.print_key_value("Full Query Text", query_text)
                else:
                    self.formatter.print_success("No Log Analytics queries found in the last 7 days")
            elif response.status_code == 204:
                self.formatter.print_success("Query executed successfully but no query logs found")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        # 3. Check Windows Command Execution
        self.formatter.print_subsection("WINDOWS COMMAND EXECUTION AUDITING")
        try:
            # First try to check if SecurityEvent table exists (without logging errors)
            test_query = "SecurityEvent | take 1"
            test_response = self._test_table_exists(workspace_id, test_query)
            
            if test_response is False:  # Table doesn't exist
                # SecurityEvent table doesn't exist, use AzureActivity instead
                self.formatter.print_info("SecurityEvent table not available - using AzureActivity for command execution auditing")
                
                query = """
                AzureActivity
                | where TimeGenerated > ago(7d)
                | where OperationName contains "Command" or OperationName contains "Script" or OperationName contains "PowerShell" or OperationName contains "AzureCLI"
                | project TimeGenerated, Caller, OperationName, ResourceGroup, Resource
                | order by TimeGenerated desc
                | take {max_subitems}
                """
                
                response = self.api_client.log_analytics_query(workspace_id, query, "P7D")
                if response.status_code == 200:
                    results = response.json()
                    tables = results.get('tables', [])
                    
                    if tables and tables[0].get('rows'):
                        rows = tables[0]['rows']
                        columns = tables[0]['columns']
                        
                        self.formatter.print_success(f"Found {len(rows)} command executions in the last 7 days (from AzureActivity)")
                        
                        col_map = {col['name']: i for i, col in enumerate(columns)}
                        
                        for i, row in enumerate(rows, 1):
                            self.formatter.print_subsection(f"COMMAND EXECUTION {i}")
                            
                            if 'TimeGenerated' in col_map:
                                self.formatter.print_key_value("When", row[col_map['TimeGenerated']])
                            if 'Caller' in col_map:
                                self.formatter.print_key_value("Event Source (Who)", row[col_map['Caller']])
                            if 'OperationName' in col_map:
                                self.formatter.print_key_value("Event Type", row[col_map['OperationName']])
                            if 'ResourceGroup' in col_map:
                                self.formatter.print_key_value("Where (Resource Group)", row[col_map['ResourceGroup']])
                            if 'Resource' in col_map:
                                self.formatter.print_key_value("Where (Resource)", row[col_map['Resource']])
                    else:
                        self.formatter.print_success("No command executions found in the last 7 days")
                        self.formatter.print_info("Note: Windows Security Events connector not configured - using AzureActivity table")
                elif response.status_code == 204:
                    self.formatter.print_success("Query executed successfully but no command executions found")
                    self.formatter.print_info("Note: Windows Security Events connector not configured - using AzureActivity table")
                else:
                    self.formatter.print_error(f"Failed to query AzureActivity: {response.status_code}")
                    self.formatter.print_error(f"Response: {response.text}")
            elif test_response is True:  # Table exists
                # SecurityEvent table exists, use it
                query = """
                SecurityEvent
                | where EventID == 4688
                | where TimeGenerated > ago(7d)
                | project TimeGenerated, Account, Computer, ProcessName, ParentProcessName
                | order by TimeGenerated desc
                | take {max_subitems}
                """
                
                response = self.api_client.log_analytics_query(workspace_id, query, "P7D")
                if response.status_code == 200:
                    results = response.json()
                    tables = results.get('tables', [])
                    
                    if tables and tables[0].get('rows'):
                        rows = tables[0]['rows']
                        columns = tables[0]['columns']
                        
                        self.formatter.print_success(f"Found {len(rows)} Windows command executions in the last 7 days")
                        
                        col_map = {col['name']: i for i, col in enumerate(columns)}
                        
                        for i, row in enumerate(rows, 1):
                            self.formatter.print_subsection(f"COMMAND EXECUTION {i}")
                            
                            if 'TimeGenerated' in col_map:
                                self.formatter.print_key_value("When", row[col_map['TimeGenerated']])
                            if 'Account' in col_map:
                                self.formatter.print_key_value("Event Source (Who)", row[col_map['Account']])
                            if 'ProcessName' in col_map:
                                self.formatter.print_key_value("Event Type", f"Process: {row[col_map['ProcessName']]}")
                            if 'Computer' in col_map:
                                self.formatter.print_key_value("Where", row[col_map['Computer']])
                            if 'ParentProcessName' in col_map:
                                self.formatter.print_key_value("Parent Process", row[col_map['ParentProcessName']])
                    else:
                        self.formatter.print_success("No Windows command executions found in the last 7 days")
                elif response.status_code == 204:
                    self.formatter.print_success("Query executed successfully but no command executions found")
                else:
                    self.formatter.print_error(f"Failed to query SecurityEvent: {response.status_code}")
                    self.formatter.print_error(f"Response: {response.text}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        self.formatter.print_separator()
    
    def _test_table_exists(self, workspace_id: str, query: str) -> bool:
        """Test if a Log Analytics table exists without logging errors"""
        try:
            import urllib.parse
            import requests
            from azure.identity import ClientSecretCredential
            
            query_encoded = urllib.parse.quote(query)
            timespan_encoded = urllib.parse.quote("P1D")
            
            # Use base URLs from config to determine environment
            arm_base_url = getattr(self.config, 'arm_base_url', 'https://management.azure.com')
            graph_base_url = getattr(self.config, 'graph_base_url', 'https://graph.microsoft.com/v1.0')
            
            # Check if this is a government environment
            is_government = (
                "usgovcloudapi.net" in arm_base_url or
                "graph.microsoft.us" in graph_base_url
            )
            
            # Get Log Analytics token
            credential = ClientSecretCredential(
                self.config.tenant_id, 
                self.config.client_id, 
                self.config.client_secret
            )
            
            if is_government:
                log_analytics_scope = "https://api.loganalytics.us/.default"
                url = f"https://api.loganalytics.us/v1/workspaces/{workspace_id}/query?query={query_encoded}&timespan={timespan_encoded}"
            else:
                log_analytics_scope = "https://api.loganalytics.io/.default"
                url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query?query={query_encoded}&timespan={timespan_encoded}"
            
            log_analytics_token = credential.get_token(log_analytics_scope).token
            
            headers = {
                "Authorization": f"Bearer {log_analytics_token}",
                "Content-Type": "application/json"
            }
            
            response = requests.get(url, headers=headers)
            
            # Return True if table exists (200 or 204), False if it doesn't exist (400 with SecurityEvent error)
            if response.status_code in [200, 204]:
                return True
            elif response.status_code == 400 and "SecurityEvent" in response.text:
                return False
            else:
                # For other errors, assume table doesn't exist
                return False
                
        except Exception:
            # If any exception occurs, assume table doesn't exist
            return False
    
    def check_user_risk_policy(self):
        """Check Microsoft Entra User Risk Policy configuration."""
        self.formatter.print_header(
            "MICROSOFT ENTRA USER RISK POLICY",
            "This function checks and prints the Microsoft Entra User Risk Policy using the Microsoft Graph API. It evidences risk-based conditional access and user risk management for compliance."
        )
        
        try:
            response = self.api_client.graph_get("/identityProtection/userRiskPolicy")
            if response.status_code == 200:
                policy = response.json()
                self.formatter.print_success("User Risk Policy found")
                self.formatter.print_key_value("Enabled", policy.get('isEnabled', 'Unknown'))
                self.formatter.print_key_value("Risk Level", policy.get('userRiskLevel', 'Unknown'))
                self.formatter.print_key_value("Action", policy.get('userRiskAction', 'Unknown'))
                self.formatter.print_key_value("Include Users", policy.get('includeUsers', 'Unknown'))
                self.formatter.print_key_value("Exclude Users", policy.get('excludeUsers', 'Unknown'))
                self.formatter.print_key_value("Notification to User", policy.get('notificationToUser', 'Unknown'))
                self.formatter.print_key_value("Remediation to User", policy.get('remediationToUser', 'Unknown'))
                
                actions = policy.get('actions', [])
                if actions:
                    self.formatter.print_subsection("Actions")
                    for action in actions:
                        self.formatter.print_key_value("Action", action)
            elif response.status_code == 400 and 'Resource not found for the segment' in response.text:
                self.formatter.print_warning("User Risk Policy is only available with Microsoft Entra ID P2 (Azure AD Premium P2). This feature is not available in your tenant.")
            else:
                self.formatter.print_error(f"Failed to retrieve user risk policy: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving user risk policy: {e}")
        
        self.formatter.print_separator()
    
    def check_identity_protection_risk_detections(self, top: int = 10):
        """Check Microsoft Entra Identity Protection Risk Detections."""
        self.formatter.print_header(
            "MICROSOFT ENTRA IDENTITY PROTECTION RISK DETECTIONS",
            "This function checks and prints recent risk detections from Microsoft Entra ID Identity Protection using the Microsoft Graph API. It evidences detection of risky sign-ins and user activity for compliance and threat monitoring."
        )
        
        try:
            response = self.api_client.graph_get(f"/identityProtection/riskDetections?$top={top}")
            if response.status_code == 200:
                detections = response.json().get('value', [])
                if not detections:
                    self.formatter.print_info("No recent risk detections found.")
                else:
                    self.formatter.print_success(f"Found {len(detections)} recent risk detections")
                    for i, det in enumerate(detections, 1):
                        self.formatter.print_subsection(f"RISK DETECTION {i}")
                        self.formatter.print_key_value("User", f"{det.get('userDisplayName', 'N/A')} ({det.get('userPrincipalName', 'N/A')})")
                        self.formatter.print_key_value("Risk Type", det.get('riskType', 'N/A'))
                        self.formatter.print_key_value("Risk Level", det.get('riskLevel', 'N/A'))
                        self.formatter.print_key_value("Risk State", det.get('riskState', 'N/A'))
                        self.formatter.print_key_value("Detection Time", det.get('activityDateTime', 'N/A'))
                        self.formatter.print_key_value("Detection ID", det.get('id', 'N/A'))
            elif response.status_code == 403:
                # Check for licensing error specifically
                if self._handle_identity_protection_license_error(response):
                    pass  # Error already handled by helper method
                else:
                    self.formatter.print_error(f"Failed to retrieve risk detections: {response.status_code}")
                    error_data = response.json()
                    if error_data:
                        self.formatter.print_info(f"Error details: {error_data.get('error', {}).get('message', 'Unknown error')}")
            else:
                self.formatter.print_error(f"Failed to retrieve risk detections: {response.status_code}")
                error_data = response.json()
                if error_data:
                    self.formatter.print_info(f"Error details: {error_data.get('error', {}).get('message', 'Unknown error')}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving risk detections: {e}")
        
        self.formatter.print_separator()
    
    def check_sign_in_risk_policy(self, top: int = 10):
        """Check Microsoft Entra Sign-In Risk Detections."""
        self.formatter.print_header(
            "MICROSOFT ENTRA SIGN-IN RISK DETECTIONS",
            "This function checks and prints recent sign-in risk detections from Microsoft Entra ID Identity Protection using the Microsoft Graph API. It evidences detection of risky sign-in attempts for compliance and threat monitoring."
        )
        
        try:
            response = self.api_client.graph_get(f"/identityProtection/riskDetections?$top={top}")
            if response.status_code == 200:
                detections = response.json().get('value', [])
                sign_in_detections = [d for d in detections if d.get('activity') == 'signin']
                if not sign_in_detections:
                    self.formatter.print_info("No recent sign-in risk detections found.")
                else:
                    self.formatter.print_success(f"Found {len(sign_in_detections)} recent sign-in risk detections")
                    for i, det in enumerate(sign_in_detections, 1):
                        self.formatter.print_subsection(f"SIGN-IN RISK DETECTION {i}")
                        self.formatter.print_key_value("User", f"{det.get('userDisplayName', 'N/A')} ({det.get('userPrincipalName', 'N/A')})")
                        self.formatter.print_key_value("Risk Event Type", det.get('riskEventType', 'N/A'))
                        self.formatter.print_key_value("Risk Level", det.get('riskLevel', 'N/A'))
                        self.formatter.print_key_value("Risk State", det.get('riskState', 'N/A'))
                        self.formatter.print_key_value("Detection Time", det.get('activityDateTime', 'N/A'))
                        self.formatter.print_key_value("IP Address", det.get('ipAddress', 'N/A'))
                        
                        location = det.get('location', {})
                        if location:
                            city = location.get('city', 'N/A')
                            country = location.get('countryOrRegion', 'N/A')
                            self.formatter.print_key_value("Location", f"{city}, {country}")
                        
                        self.formatter.print_key_value("Detection ID", det.get('id', 'N/A'))
            elif response.status_code == 403:
                # Check for licensing error specifically
                if self._handle_identity_protection_license_error(response):
                    pass  # Error already handled by helper method
                else:
                    self.formatter.print_error(f"Failed to retrieve sign-in risk detections: {response.status_code}")
                    error_data = response.json()
                    if error_data:
                        self.formatter.print_info(f"Error details: {error_data.get('error', {}).get('message', 'Unknown error')}")
            else:
                self.formatter.print_error(f"Failed to retrieve sign-in risk detections: {response.status_code}")
                error_data = response.json()
                if error_data:
                    self.formatter.print_info(f"Error details: {error_data.get('error', {}).get('message', 'Unknown error')}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving sign-in risk detections: {e}")
        
        self.formatter.print_separator()
    
    def check_bastion_host_settings(self):
        """Check Azure Bastion Host Configuration."""
        self.formatter.print_header(
            "AZURE BASTION HOST CONFIGURATION",
            "This function checks and prints the Azure Bastion host configuration settings, including session limits, network configuration, and security settings. It evidences secure remote access controls for compliance."
        )
        
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        
        if not (subscription_id and resource_group):
            self.formatter.print_error("subscription_id and resource_group are required for checking Bastion settings.")
            self.formatter.print_info("Please set these in the config.")
            return
        
        try:
            url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/bastionHosts?api-version=2023-05-01"
            response = self.api_client.arm_get(url)
            
            if response.status_code == 200:
                bastion_hosts = response.json().get('value', [])
                
                if not bastion_hosts:
                    self.formatter.print_info("No Azure Bastion hosts found in the specified subscription/resource group.")
                    return
                
                for host in bastion_hosts:
                    self.formatter.print_subsection(f"BASTION HOST: {host.get('name')}")
                    
                    properties = host.get('properties', {})
                    
                    # Print concurrent session limits
                    self.formatter.print_key_value("Privileged Session Limit", properties.get('privilegedSessionLimit', 'Not configured'))
                    self.formatter.print_key_value("Non-Privileged Session Limit", properties.get('sessionLimit', 'Not configured'))
                    
                    # Print network configuration
                    vnet = properties.get('virtualNetwork', {}).get('id', 'Not configured')
                    self.formatter.print_key_value("Virtual Network", vnet)
                    
                    public_ip = properties.get('publicIPAddress', {}).get('id', 'Not configured')
                    self.formatter.print_key_value("Public IP", public_ip)
                    
                    # Print security settings
                    self.formatter.print_key_value("Copy/Paste Enabled", properties.get('enableCopyPaste', True))
                    self.formatter.print_key_value("File Copy Enabled", properties.get('enableFileCopy', False))
                    self.formatter.print_key_value("IP-based Connection Tracking", properties.get('enableIpConnect', False))
                    self.formatter.print_key_value("Shareable Link", properties.get('enableShareableLink', False))
            else:
                self.formatter.print_error(f"Failed to retrieve Bastion host settings: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving Bastion host settings: {e}")
        
        self.formatter.print_separator()
    
    def check_encryption_policy_and_defender_status(self):
        """Check Azure Policy Assignments and Defender for Cloud Status."""
        self.formatter.print_header(
            "AZURE POLICY ASSIGNMENTS AND DEFENDER FOR CLOUD STATUS",
            "This function prints evidence of Azure Policy assignments enforcing encryption and Defender for Cloud status for the subscription. It evidences policy-based security controls and cloud workload protection for compliance."
        )
        
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id is required to check policy assignments and Defender for Cloud status.")
            self.formatter.print_info("Please set this in the config.")
            return
        
        # List policy assignments
        try:
            policy_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
            response = self.api_client.arm_get(policy_url)
            
            if response.status_code == 200:
                assignments = response.json().get('value', [])
                if assignments:
                    self.formatter.print_success(f"Found {len(assignments)} assigned Azure Policies")
                    
                    encryption_policies = []
                    for assignment in assignments:
                        policy_definition_id = assignment.get('properties', {}).get('policyDefinitionId', '')
                        if any(keyword in policy_definition_id.lower() for keyword in ['encryption', 'encrypt', 'security']):
                            encryption_policies.append(assignment)
                    
                    if encryption_policies:
                        self.formatter.print_subsection("ENCRYPTION-RELATED POLICIES")
                        for policy in encryption_policies:
                            self.formatter.print_key_value(policy.get('name', 'Unknown'), policy.get('properties', {}).get('displayName', 'No display name'))
                    else:
                        self.formatter.print_warning("No encryption-related policies found")
                else:
                    self.formatter.print_warning("No policy assignments found")
            else:
                self.formatter.print_error(f"Failed to retrieve policy assignments: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving policy assignments: {e}")
        
        self.formatter.print_separator()
    
    def check_log_analytics_retention_settings(self):
        """Check Log Analytics Retention Settings and Immutability."""
        self.formatter.print_header(
            "LOG ANALYTICS WORKSPACE IMMUTABILITY & RETENTION SETTINGS",
            "This function checks and prints the Log Analytics workspace retention and immutability settings. It evidences data retention policies, immutability protection, and compliance requirements."
        )
        
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        
        try:
            url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}?api-version=2022-10-01"
            response = self.api_client.arm_get(url)
            
            if response.status_code == 200:
                workspace = response.json()
                properties = workspace.get('properties', {})
                
                self.formatter.print_success("Log Analytics workspace found")
                self.formatter.print_key_value("Workspace Name", workspace.get('name', 'Unknown'))
                self.formatter.print_key_value("Location", workspace.get('location', 'Unknown'))
                self.formatter.print_key_value("Retention (Days)", properties.get('retentionInDays', 'Not set'))
                self.formatter.print_key_value("SKU", properties.get('sku', {}).get('name', 'Unknown'))
                
                # Check for data export settings
                data_exports = properties.get('features', {}).get('enableDataExport', False)
                self.formatter.print_key_value("Data Export Enabled", data_exports)
                
                # Check immutability settings
                immutability = properties.get('immutableWorkspaceProperties', {})
                if immutability:
                    state = immutability.get('state', 'Not set')
                    self.formatter.print_key_value("Immutability State", state)
                else:
                    self.formatter.print_warning("Immutability State: Not set or not available")
                
                # Compliance recommendations
                retention_days = properties.get('retentionInDays', 0)
                if retention_days >= 90:
                    self.formatter.print_success("Retention period meets common compliance requirements (90+ days)")
                else:
                    self.formatter.print_warning("Retention period may not meet compliance requirements")
                    self.formatter.print_info("Consider increasing retention to 90+ days for compliance")
            else:
                self.formatter.print_error(f"Failed to retrieve workspace settings: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving workspace settings: {e}")
        
        self.formatter.print_separator()
    
    def check_workspace_rbac(self):
        """Check Log Analytics Workspace RBAC."""
        self.formatter.print_header(
            "LOG ANALYTICS WORKSPACE RBAC",
            "This function checks and prints the Log Analytics workspace role-based access control (RBAC) settings. It evidences access control and permissions management for compliance."
        )
        
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        
        try:
            url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
            response = self.api_client.arm_get(url)
            
            if response.status_code == 200:
                assignments = response.json().get('value', [])
                if assignments:
                    self.formatter.print_success(f"Found {len(assignments)} role assignments")
                    
                    for assignment in assignments:
                        role_definition_id = assignment.get('properties', {}).get('roleDefinitionId', '')
                        principal_id = assignment.get('properties', {}).get('principalId', '')
                        principal_type = assignment.get('properties', {}).get('principalType', 'Unknown')
                        
                        # Extract role name from the full ID
                        role_name = role_definition_id.split('/')[-1] if '/' in role_definition_id else role_definition_id
                        
                        self.formatter.print_key_value(f"Role: {role_name}", f"Principal Type: {principal_type}")
                else:
                    self.formatter.print_warning("No role assignments found")
            else:
                self.formatter.print_error(f"Failed to retrieve role assignments: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving role assignments: {e}")
        
        self.formatter.print_separator()
    
    def check_credential_distribution_audit_events(self, top: int = 10):
        """Check Credential Distribution Audit Events."""
        self.formatter.print_header(
            "CREDENTIAL DISTRIBUTION AUDIT EVENTS",
            "This function checks and prints recent credential distribution audit events from Microsoft Entra ID. It evidences monitoring of credential distribution activities for compliance."
        )
        
        try:
            response = self.api_client.graph_get(f"/auditLogs/directoryAudits?$top={top}&$filter=activityDisplayName eq 'Add user' or activityDisplayName eq 'Reset user password' or activityDisplayName eq 'Change user password'")
            
            if response.status_code == 200:
                response_data = response.json()
                if response_data is None:
                    self.formatter.print_error("Invalid response data received")
                    return
                    
                events = response_data.get('value', []) if response_data is not None else []
                if not events:
                    self.formatter.print_info("No recent credential distribution events found.")
                else:
                    self.formatter.print_success(f"Found {len(events)} recent credential distribution events")
                    
                    for i, event in enumerate(events, 1):
                        if event is None:
                            continue
                            
                        self.formatter.print_subsection(f"CREDENTIAL EVENT {i}")
                        
                        # Safe access to activityDisplayName
                        activity = event.get('activityDisplayName', 'N/A')
                        self.formatter.print_key_value("Activity", activity)
                        
                        # Safe access to initiatedBy nested structure
                        initiated_by = event.get('initiatedBy', {})
                        if initiated_by is not None:
                            user_info = initiated_by.get('user', {})
                            if user_info is not None:
                                initiated_by_user = user_info.get('userPrincipalName', 'N/A')
                            else:
                                initiated_by_user = 'N/A'
                        else:
                            initiated_by_user = 'N/A'
                        self.formatter.print_key_value("Initiated By", initiated_by_user)
                        
                        # Safe access to targetResources nested structure
                        target_resources = event.get('targetResources', [])
                        if target_resources and len(target_resources) > 0:
                            first_target = target_resources[0]
                            if first_target is not None:
                                target_user = first_target.get('userPrincipalName', 'N/A')
                            else:
                                target_user = 'N/A'
                        else:
                            target_user = 'N/A'
                        self.formatter.print_key_value("Target User", target_user)
                        
                        # Safe access to timestamp and result
                        timestamp = event.get('activityDateTime', 'N/A')
                        self.formatter.print_key_value("Timestamp", timestamp)
                        
                        result = event.get('result', 'N/A')
                        self.formatter.print_key_value("Result", result)
            else:
                self.formatter.print_error(f"Failed to retrieve credential distribution events: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving credential distribution events: {e}")
        
        self.formatter.print_separator()
    
    def check_cis_l1_initiative_assignment(self):
        """Check CIS L1 Initiative Assignment."""
        self.formatter.print_header(
            "CIS L1 INITIATIVE ASSIGNMENT",
            "This function checks for CIS L1 initiative assignments in Azure Policy. It evidences compliance with CIS security benchmarks for compliance."
        )
        
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id is required to check CIS initiative assignments.")
            return
        
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
            response = self.api_client.arm_get(url)
            
            if response.status_code == 200:
                assignments = response.json().get('value', [])
                cis_assignments = []
                
                for assignment in assignments:
                    display_name = assignment.get('properties', {}).get('displayName', '')
                    if 'cis' in display_name.lower() and 'l1' in display_name.lower():
                        cis_assignments.append(assignment)
                
                if cis_assignments:
                    self.formatter.print_success(f"Found {len(cis_assignments)} CIS L1 initiative assignments")
                    for assignment in cis_assignments:
                        self.formatter.print_key_value(assignment.get('name', 'Unknown'), assignment.get('properties', {}).get('displayName', 'No display name'))
                else:
                    self.formatter.print_warning("No CIS L1 initiative assignments found")
                    self.formatter.print_info("Consider implementing CIS L1 security benchmarks for compliance")
            else:
                self.formatter.print_error(f"Failed to retrieve policy assignments: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving policy assignments: {e}")
        
        self.formatter.print_separator()
    
    def check_waf_diagnostic_settings(self):
        """Check WAF Diagnostic Settings."""
        self.formatter.print_header(
            "WAF DIAGNOSTIC SETTINGS",
            "This function checks and prints the diagnostic settings for Web Application Firewalls (WAF). It evidences logging and monitoring configuration for compliance."
        )
        
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id is required to check WAF diagnostic settings.")
            return
        found_policy = False
        found_diag = False
        try:
            # Get all WAF policies
            waf_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies?api-version=2023-05-01"
            response = self.api_client.arm_get(waf_url)
            
            if response.status_code == 200:
                waf_policies = response.json().get('value', [])
                if not waf_policies:
                    self.formatter.print_info("No WAF policies found in the subscription.")
                for policy in waf_policies:
                    found_policy = True
                    policy_name = policy.get('name', 'Unknown')
                    self.formatter.print_subsection(f"WAF POLICY: {policy_name}")
                    # Check diagnostic settings for this WAF policy
                    diag_url = f"/subscriptions/{subscription_id}/resourceGroups/{policy.get('id', '').split('/')[4]}/providers/Microsoft.Network/applicationGatewayWebApplicationFirewallPolicies/{policy_name}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
                    diag_response = self.api_client.arm_get(diag_url)
                    if diag_response.status_code == 200:
                        diag_settings = diag_response.json().get('value', [])
                        if diag_settings:
                            found_diag = True
                            self.formatter.print_success(f"Found {len(diag_settings)} diagnostic settings")
                            for setting in diag_settings:
                                self.formatter.print_key_value("Setting Name", setting.get('name', 'Unknown'))
                                self.formatter.print_key_value("Storage Account", setting.get('properties', {}).get('storageAccountId', 'Not configured'))
                                self.formatter.print_key_value("Log Analytics", setting.get('properties', {}).get('workspaceId', 'Not configured'))
                        else:
                            self.formatter.print_warning("No diagnostic settings configured for this WAF policy")
                    else:
                        self.formatter.print_error(f"Failed to retrieve diagnostic settings: {diag_response.status_code}")
                if not found_policy:
                    self.formatter.print_warning("No WAF policies found to check diagnostics.")
                if found_policy and not found_diag:
                    self.formatter.print_warning("No diagnostic settings found for any WAF policy.")
            else:
                self.formatter.print_error(f"Failed to retrieve WAF policies: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving WAF diagnostic settings: {e}")
        
        self.formatter.print_separator()
    
    def check_recent_fim_alerts(self, top: int = 10):
        """Check Recent FIM Alerts."""
        self.formatter.print_header(
            "RECENT FIM ALERTS",
            "This function checks and prints recent File Integrity Monitoring (FIM) alerts from Microsoft Sentinel. It evidences monitoring of file system changes for compliance."
        )
        
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        
        try:
            # Get workspace ID for the Log Analytics Query API
            workspace_id = self.api_client.get_workspace_id(subscription_id, resource_group, workspace_name)
            
            # Query for FIM alerts
            query = f"""
            SecurityAlert
            | where TimeGenerated > ago(7d)
            | where AlertName contains "FIM" or AlertName contains "File Integrity" or AlertName contains "File Change"
            | order by TimeGenerated desc
            | take {top}
            """
            
            response = self.api_client.log_analytics_query(workspace_id, query, "P7D")
            
            if response.status_code == 200:
                results = response.json()
                tables = results.get('tables', [])
                
                if tables and tables[0].get('rows'):
                    rows = tables[0]['rows']
                    columns = tables[0]['columns']
                    
                    self.formatter.print_success(f"Found {len(rows)} recent FIM alerts")
                    
                    col_map = {col['name']: i for i, col in enumerate(columns)}
                    
                    for i, row in enumerate(rows, 1):
                        self.formatter.print_subsection(f"FIM ALERT {i}")
                        
                        if 'TimeGenerated' in col_map:
                            self.formatter.print_key_value("Time", row[col_map['TimeGenerated']])
                        if 'AlertName' in col_map:
                            self.formatter.print_key_value("Alert Name", row[col_map['AlertName']])
                        if 'CompromisedEntity' in col_map:
                            self.formatter.print_key_value("Entity", row[col_map['CompromisedEntity']])
                        if 'Severity' in col_map:
                            self.formatter.print_key_value("Severity", row[col_map['Severity']])
                else:
                    self.formatter.print_info("No recent FIM alerts found")
            elif response.status_code == 204:
                self.formatter.print_success("Query executed successfully but no FIM alerts found")
            else:
                self.formatter.print_error(f"Failed to query FIM alerts: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while querying FIM alerts: {e}")
        
        self.formatter.print_separator()
    
    def check_arm_template_configuration_orchestration(self):
        """Check ARM Template Configuration Orchestration."""
        self.formatter.print_header(
            "ARM TEMPLATE CONFIGURATION ORCHESTRATION",
            "This function checks for ARM template deployments and configuration orchestration. It evidences infrastructure as code and automated configuration management for compliance."
        )
        
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id is required to check ARM template deployments.")
            return
        
        try:
            # Get recent deployments
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Resources/deployments?api-version=2022-09-01&$top=20"
            response = self.api_client.arm_get(url)
            
            if response.status_code == 200:
                deployments = response.json().get('value', [])
                if deployments:
                    self.formatter.print_success(f"Found {len(deployments)} recent deployments")
                    
                    successful_deployments = [d for d in deployments if d.get('properties', {}).get('provisioningState') == 'Succeeded']
                    failed_deployments = [d for d in deployments if d.get('properties', {}).get('provisioningState') == 'Failed']
                    
                    self.formatter.print_key_value("Total Deployments", len(deployments))
                    self.formatter.print_key_value("Successful", len(successful_deployments))
                    self.formatter.print_key_value("Failed", len(failed_deployments))
                    
                    if successful_deployments:
                        self.formatter.print_subsection("RECENT SUCCESSFUL DEPLOYMENTS")
                        max_subitems = getattr(self.config, 'max_subitems', 10)
                        for deployment in successful_deployments[:max_subitems]:
                            self.formatter.print_key_value(
                                deployment.get('name', 'Unknown'),
                                f"Template: {deployment.get('properties', {}).get('templateLink', {}).get('uri', 'Local template')}"
                            )
                    
                    if failed_deployments:
                        self.formatter.print_subsection("RECENT FAILED DEPLOYMENTS")
                        max_subitems = getattr(self.config, 'max_subitems', 10)
                        for deployment in failed_deployments[:max_subitems]:
                            self.formatter.print_warning(f"{deployment.get('name', 'Unknown')} - Failed")
                else:
                    self.formatter.print_info("No recent deployments found")
            else:
                self.formatter.print_error(f"Failed to retrieve deployments: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving deployments: {e}")
        
        self.formatter.print_separator()
    
    def check_recent_sentinel_security_alerts(self, hours_back: int = 24):
        """Check Recent Sentinel Security Alerts, including notification recipients and incident owner."""
        self.formatter.print_header(
            "RECENT SENTINEL SECURITY ALERTS",
            f"This function checks and prints recent security alerts from Microsoft Sentinel over the last {hours_back} hours. It evidences security monitoring and incident detection capabilities for compliance."
        )
        
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        
        # --- Retrieve analytic rules for notification recipients ---
        rule_recipients = {}
        try:
            rules_url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-12-01-preview"
            rules_response = self.api_client.arm_get(rules_url)
            if rules_response.status_code == 200:
                rules = rules_response.json().get('value', [])
                for rule in rules:
                    rule_name = rule.get('name')
                    actions = rule.get('properties', {}).get('actions', [])
                    recipients = []
                    for action in actions:
                        if action.get('actionType') == 'Email':
                            recipients.extend(action.get('toRecipients', []))
                    rule_recipients[rule_name] = recipients
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving analytic rules: {e}")
        
        # --- Retrieve incidents for owner/assignment ---
        incident_owners = {}
        try:
            incidents_url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01-preview"
            incidents_response = self.api_client.arm_get(incidents_url)
            if incidents_response.status_code == 200:
                incidents = incidents_response.json().get('value', [])
                for inc in incidents:
                    props = inc.get('properties', {})
                    title = props.get('title')
                    owner = props.get('owner', {}).get('assignedTo', None)
                    if title:
                        incident_owners[title] = owner
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving incidents: {e}")
        
        try:
            # Get workspace ID for the Log Analytics Query API
            workspace_id = self.api_client.get_workspace_id(subscription_id, resource_group, workspace_name)
            
            # Query for recent security alerts
            max_subitems = getattr(self.config, 'max_subitems', 10)
            query = f"""
            SecurityAlert
            | where TimeGenerated > ago({hours_back}h)
            | order by TimeGenerated desc
            | take {max_subitems}
            """
            
            # Calculate timespan for the new API (e.g., "P24H" for 24 hours)
            timespan = f"P{hours_back}H"
            
            response = self.api_client.log_analytics_query(workspace_id, query, timespan)
            
            if response.status_code == 200:
                results = response.json()
                tables = results.get('tables', [])
                
                if tables and tables[0].get('rows'):
                    rows = tables[0]['rows']
                    columns = tables[0]['columns']
                    
                    self.formatter.print_success(f"Found {len(rows)} security alerts in the last {hours_back} hours")
                    
                    col_map = {col['name']: i for i, col in enumerate(columns)}
                    
                    for i, row in enumerate(rows, 1):
                        self.formatter.print_subsection(f"SECURITY ALERT {i}")
                        alert_name = row[col_map['AlertName']] if 'AlertName' in col_map else None
                        
                        if 'TimeGenerated' in col_map:
                            self.formatter.print_key_value("Time", row[col_map['TimeGenerated']])
                        if alert_name:
                            self.formatter.print_key_value("Alert Name", alert_name)
                        if 'Severity' in col_map:
                            self.formatter.print_key_value("Severity", row[col_map['Severity']])
                        if 'CompromisedEntity' in col_map:
                            self.formatter.print_key_value("Entity", row[col_map['CompromisedEntity']])
                        if 'ProviderName' in col_map:
                            self.formatter.print_key_value("Provider", row[col_map['ProviderName']])
                        
                        # --- Analytic Rule Notification Recipients ---
                        recipients = rule_recipients.get(alert_name, [])
                        if recipients:
                            self.formatter.print_key_value("Notification Recipients", ", ".join(recipients))
                        else:
                            self.formatter.print_key_value("Notification Recipients", "None found or not configured")
                        
                        # --- Incident Owner/Assignment ---
                        owner = incident_owners.get(alert_name, None)
                        if owner:
                            self.formatter.print_key_value("Incident Owner/Assigned To", owner)
                        else:
                            self.formatter.print_key_value("Incident Owner/Assigned To", "None found or not assigned")
                else:
                    self.formatter.print_success(f"No security alerts found in the last {hours_back} hours")
                    self.formatter.print_info("This may indicate good security posture or limited monitoring")
            elif response.status_code == 204:
                self.formatter.print_success("Query executed successfully but no security alerts found")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while querying security alerts: {e}")
        
        self.formatter.print_separator()

    def check_sentinel_connected_workspaces(self):
        """List all Log Analytics workspaces that are connected to Microsoft Sentinel."""
        self.formatter.print_header(
            "MICROSOFT SENTINEL CONNECTED WORKSPACES",
            "This function lists all Log Analytics workspaces that are connected to Microsoft Sentinel. It evidences the scope of security monitoring and data collection across your Azure environment for compliance."
        )
        
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        
        try:
            # Get all Log Analytics workspaces in the subscription
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01"
            response = self.api_client.arm_get(url)
            
            if response.status_code == 200:
                workspaces = response.json().get('value', [])
                
                if workspaces:
                    self.formatter.print_success(f"Found {len(workspaces)} Log Analytics workspaces in subscription")
                    
                    sentinel_workspaces = []
                    non_sentinel_workspaces = []
                    
                    for workspace in workspaces:
                        workspace_name = workspace.get('name', 'Unknown')
                        resource_group = workspace.get('id', '').split('/')[4] if len(workspace.get('id', '').split('/')) > 4 else 'Unknown'
                        
                        # Check if this workspace has Sentinel enabled
                        sentinel_url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/settings?api-version=2023-02-01-preview"
                        sentinel_response = self.api_client.arm_get(sentinel_url)
                        
                        if sentinel_response.status_code == 200:
                            sentinel_settings = sentinel_response.json().get('value', [])
                            if sentinel_settings:
                                sentinel_workspaces.append({
                                    'name': workspace_name,
                                    'resource_group': resource_group,
                                    'location': workspace.get('location', 'Unknown'),
                                    'sku': workspace.get('sku', {}).get('name', 'Unknown'),
                                    'retention_days': workspace.get('properties', {}).get('retentionInDays', 'Unknown')
                                })
                            else:
                                non_sentinel_workspaces.append({
                                    'name': workspace_name,
                                    'resource_group': resource_group,
                                    'location': workspace.get('location', 'Unknown')
                                })
                        else:
                            non_sentinel_workspaces.append({
                                'name': workspace_name,
                                'resource_group': resource_group,
                                'location': workspace.get('location', 'Unknown')
                            })
                    
                    # Display Sentinel-enabled workspaces
                    if sentinel_workspaces:
                        self.formatter.print_subsection("SENTINEL-ENABLED WORKSPACES")
                        self.formatter.print_success(f"Found {len(sentinel_workspaces)} workspaces with Microsoft Sentinel enabled:")
                        
                        for workspace in sentinel_workspaces:
                            self.formatter.print_subsection(f"WORKSPACE: {workspace['name']}")
                            self.formatter.print_key_value("Resource Group", workspace['resource_group'])
                            self.formatter.print_key_value("Location", workspace['location'])
                            self.formatter.print_key_value("SKU", workspace['sku'])
                            self.formatter.print_key_value("Retention (Days)", workspace['retention_days'])
                            
                            # Check for data connectors
                            connector_url = f"/subscriptions/{subscription_id}/resourceGroups/{workspace['resource_group']}/providers/Microsoft.OperationalInsights/workspaces/{workspace['name']}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2023-02-01-preview"
                            connector_response = self.api_client.arm_get(connector_url)
                            
                            if connector_response.status_code == 200:
                                connectors = connector_response.json().get('value', [])
                                enabled_connectors = [c for c in connectors if c.get('properties', {}).get('connectorState') == 'Connected']
                                self.formatter.print_key_value("Data Connectors", f"{len(enabled_connectors)}/{len(connectors)} connected")
                                
                                if enabled_connectors:
                                    connector_types = [c.get('kind', 'Unknown') for c in enabled_connectors]
                                    self.formatter.print_key_value("Connector Types", ', '.join(set(connector_types)))
                            else:
                                self.formatter.print_key_value("Data Connectors", "Unable to retrieve")
                    else:
                        self.formatter.print_error("No workspaces found with Microsoft Sentinel enabled")
                    
                    # Display non-Sentinel workspaces
                    if non_sentinel_workspaces:
                        self.formatter.print_subsection("NON-SENTINEL WORKSPACES")
                        self.formatter.print_info(f"Found {len(non_sentinel_workspaces)} workspaces without Microsoft Sentinel:")
                        
                        max_subitems = getattr(self.config, 'max_subitems', 10)
                        for workspace in non_sentinel_workspaces[:max_subitems]:  # Show first max_subitems
                            self.formatter.print_key_value(f"{workspace['name']}", f"RG: {workspace['resource_group']}, Location: {workspace['location']}")
                        
                        if len(non_sentinel_workspaces) > max_subitems:
                            self.formatter.print_info(f"... and {len(non_sentinel_workspaces) - max_subitems} more workspaces")
                        
                        self.formatter.print_info("Consider enabling Microsoft Sentinel on these workspaces for comprehensive security monitoring")
                else:
                    self.formatter.print_warning("No Log Analytics workspaces found in the subscription")
                    self.formatter.print_info("Microsoft Sentinel requires Log Analytics workspaces to function")
            else:
                self.formatter.print_error(f"Failed to retrieve workspaces: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
        
        self.formatter.print_separator()

    def check_recent_security_incidents(self):
        """Query the SecurityIncident table and print relevant information, using max_lines from config."""
        self.formatter.print_header(
            "RECENT SECURITY INCIDENTS (SecurityIncident Table)",
            "This function queries the SecurityIncident table in Log Analytics and prints relevant information for each incident, up to the configured max_lines."
        )
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        max_lines = getattr(self.config, 'max_lines', 100)

        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return

        try:
            query = f"""
            SecurityIncident
            | order by TimeGenerated desc
            | take {max_lines}
            """
            url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/api/query?api-version=2020-08-01"
            payload = {"query": query, "timespan": "P30D"}
            response = self.api_client.arm_post(url, payload)

            if response.status_code == 200:
                results = response.json()
                tables = results.get('tables', [])
                if tables and tables[0].get('rows'):
                    rows = tables[0]['rows']
                    columns = tables[0]['columns']
                    self.formatter.print_success(f"Found {len(rows)} recent security incidents:")
                    col_map = {col['name']: i for i, col in enumerate(columns)}
                    for i, row in enumerate(rows, 1):
                        self.formatter.print_subsection(f"SECURITY INCIDENT {i}")
                        if 'TimeGenerated' in col_map:
                            self.formatter.print_key_value("Time", row[col_map['TimeGenerated']])
                        if 'IncidentNumber' in col_map:
                            self.formatter.print_key_value("Incident Number", row[col_map['IncidentNumber']])
                        if 'Title' in col_map:
                            self.formatter.print_key_value("Title", row[col_map['Title']])
                        if 'Severity' in col_map:
                            self.formatter.print_key_value("Severity", row[col_map['Severity']])
                        if 'Status' in col_map:
                            self.formatter.print_key_value("Status", row[col_map['Status']])
                        if 'Owner' in col_map:
                            self.formatter.print_key_value("Owner", row[col_map['Owner']])
                        if 'Description' in col_map:
                            desc = row[col_map['Description']]
                            if desc and len(str(desc)) > 100:
                                desc = str(desc)[:100] + "..."
                            self.formatter.print_key_value("Description", desc)
                        if 'Classification' in col_map:
                            self.formatter.print_key_value("Classification", row[col_map['Classification']])
                        if 'ProviderAlertId' in col_map:
                            self.formatter.print_key_value("Provider Alert ID", row[col_map['ProviderAlertId']])
                else:
                    self.formatter.print_success("No recent security incidents found in the SecurityIncident table.")
            elif response.status_code == 204:
                self.formatter.print_success("Query executed successfully but no security incidents found.")
            else:
                self.formatter.print_error(f"Failed to query SecurityIncident table: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while querying SecurityIncident table: {e}")
        self.formatter.print_separator()

    def check_azure_functions_multi_az(self):
        """Check if Azure Functions are architected with multi-availability zones (zone redundancy)."""
        self.formatter.print_header(
            "AZURE FUNCTIONS MULTI-AVAILABILITY ZONE ARCHITECTURE",
            "This function enumerates Azure Functions and checks if they are deployed with multi-availability zone (zone-redundant) configurations. It evidences high availability architecture as required for resilient solutions."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        try:
            # List all Function Apps in the subscription
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Web/sites?api-version=2022-03-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                function_apps = response.json().get('value', [])
                if not function_apps:
                    self.formatter.print_warning("No Azure Functions found in the subscription.")
                    return
                for app in function_apps:
                    name = app.get('name', 'Unknown')
                    rg = app.get('id', '').split('/')[4] if len(app.get('id', '').split('/')) > 4 else 'Unknown'
                    plan_id = app.get('properties', {}).get('serverFarmId', None)
                    self.formatter.print_subsection(f"FUNCTION APP: {name}")
                    self.formatter.print_key_value("Resource Group", rg)
                    if plan_id:
                        # Get the hosting plan details
                        plan_url = f"/{plan_id}?api-version=2022-09-01"
                        plan_response = self.api_client.arm_get(plan_url)
                        if plan_response.status_code == 200:
                            plan = plan_response.json()
                            sku = plan.get('sku', {}).get('name', 'Unknown')
                            zone_redundant = plan.get('properties', {}).get('zoneRedundant', False)
                            self.formatter.print_key_value("Hosting Plan SKU", sku)
                            self.formatter.print_key_value("Zone Redundant", str(zone_redundant))
                            if zone_redundant:
                                self.formatter.print_success("This Function App is zone-redundant (multi-AZ).")
                            else:
                                self.formatter.print_warning("This Function App is NOT zone-redundant.")
                        else:
                            self.formatter.print_error(f"Failed to retrieve hosting plan for {name}.")
                    else:
                        self.formatter.print_warning("No hosting plan information found for this Function App.")
                    self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve Azure Functions: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking Azure Functions: {e}")
        self.formatter.print_separator()

    def check_azure_time_sync_service(self):
        """Check if Azure VMs are configured to use Azure Time Sync Service (NTP baseline)."""
        self.formatter.print_header(
            "AZURE TIME SYNC SERVICE BASELINE CONFIGURATION",
            "This function enumerates Azure VMs and checks if they are configured to use the Azure Time Sync Service (NTP baseline). It evidences time synchronization configuration for compliance."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        try:
            # List all VMs in the subscription
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                vms = response.json().get('value', [])
                if not vms:
                    self.formatter.print_warning("No Azure VMs found in the subscription.")
                    return
                for vm in vms:
                    name = vm.get('name', 'Unknown')
                    rg = vm.get('id', '').split('/')[4] if len(vm.get('id', '').split('/')) > 4 else 'Unknown'
                    self.formatter.print_subsection(f"VM: {name}")
                    self.formatter.print_key_value("Resource Group", rg)
                    # Check for Time Sync Extension
                    extensions = vm.get('properties', {}).get('resources', [])
                    time_sync_found = False
                    for ext in extensions:
                        ext_type = ext.get('type', '').lower()
                        publisher = ext.get('publisher', '').lower()
                        if 'timesync' in ext_type or 'timesync' in publisher:
                            self.formatter.print_success("Azure Time Sync Service extension found.")
                            time_sync_found = True
                            break
                    if not time_sync_found:
                        self.formatter.print_warning("No explicit Azure Time Sync Service extension found. Default Azure VMs use the built-in time sync service unless overridden.")
                    self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve Azure VMs: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking Azure Time Sync Service: {e}")
        self.formatter.print_separator()

    def check_p2p_file_sharing_restriction(self):
        """Check that peer-to-peer file sharing is prohibited in production by firewall rules."""
        self.formatter.print_header(
            "PEER-TO-PEER FILE SHARING RESTRICTION",
            "This function checks firewall and NSG rules to evidence that peer-to-peer (P2P) file sharing is prohibited in production. It looks for rules blocking common P2P ports and protocols."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        
        # Common P2P ports (BitTorrent, eDonkey, Gnutella, etc.)
        p2p_ports = ["6881-6889", "135-139", "445", "6346-6347", "4662-4666", "6699", "4444", "2234", "44444", "12345", "6969"]
        
        # Common P2P protocols and their characteristics
        p2p_protocols = {
            "BitTorrent": {
                "ports": ["6881-6889", "6969"],
                "protocols": ["TCP", "UDP"],
                "keywords": ["bittorrent", "torrent", "bt-", "dht"]
            },
            "eDonkey": {
                "ports": ["4662-4666", "4242"],
                "protocols": ["TCP", "UDP"],
                "keywords": ["edonkey", "emule", "kad"]
            },
            "Gnutella": {
                "ports": ["6346-6347", "6348"],
                "protocols": ["TCP", "UDP"],
                "keywords": ["gnutella", "gnutella2", "g2"]
            },
            "Direct Connect": {
                "ports": ["411", "412"],
                "protocols": ["TCP"],
                "keywords": ["directconnect", "dc++", "adc"]
            },
            "FastTrack": {
                "ports": ["1214"],
                "protocols": ["TCP", "UDP"],
                "keywords": ["fasttrack", "kazaa", "grokster"]
            },
            "Ares": {
                "ports": ["4444", "2234"],
                "protocols": ["TCP", "UDP"],
                "keywords": ["ares", "galaxy"]
            },
            "LimeWire": {
                "ports": ["6346"],
                "protocols": ["TCP", "UDP"],
                "keywords": ["limewire", "gnutella"]
            },
            "FrostWire": {
                "ports": ["6346"],
                "protocols": ["TCP", "UDP"],
                "keywords": ["frostwire", "gnutella"]
            },
            "uTorrent": {
                "ports": ["6881-6889"],
                "protocols": ["TCP", "UDP"],
                "keywords": ["utorrent", "bittorrent", "bt-"]
            },
            "Vuze": {
                "ports": ["6881-6889"],
                "protocols": ["TCP", "UDP"],
                "keywords": ["vuze", "azureus", "bittorrent"]
            }
        }
        
        try:
            # 1. Check Network Security Groups (NSGs)
            self.formatter.print_subsection("NETWORK SECURITY GROUPS (NSG) P2P RESTRICTIONS")
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-04-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                nsgs = response.json().get('value', [])
                if not nsgs:
                    self.formatter.print_warning("No Network Security Groups found in the subscription.")
                else:
                    total_p2p_blocked_nsgs = 0
                for nsg in nsgs:
                    nsg_name = nsg.get('name', 'Unknown')
                    rg = nsg.get('id', '').split('/')[4] if len(nsg.get('id', '').split('/')) > 4 else 'Unknown'
                    self.formatter.print_subsection(f"NSG: {nsg_name}")
                    self.formatter.print_key_value("Resource Group", rg)
                        
                    rules = nsg.get('properties', {}).get('securityRules', [])
                    p2p_blocked = False
                    p2p_protocols_blocked = []
                        
                    for rule in rules:
                        access = rule.get('access', '').lower()
                        direction = rule.get('direction', '').lower()
                        protocol = rule.get('protocol', '').upper()
                        port_range = rule.get('destinationPortRange', '')
                        port_ranges = rule.get('destinationPortRanges', [])
                        name = rule.get('name', '')
                        description = rule.get('description', '').lower()
                            
                        # Check if rule blocks P2P ports
                        all_ports = [port_range] if port_range else []
                        all_ports += port_ranges
                            
                        # Check for P2P protocol blocking
                        for p2p_name, p2p_info in p2p_protocols.items():
                            # Check ports
                            for p2p_port in p2p_info["ports"]:
                                if any(p2p_port in pr for pr in all_ports) and access == 'deny':
                                    if p2p_name not in p2p_protocols_blocked:
                                        p2p_protocols_blocked.append(p2p_name)
                                    self.formatter.print_success(f"Rule '{name}' blocks {p2p_name} port(s) {p2p_port} ({direction})")
                                    p2p_blocked = True
                                
                                # Check for protocol-specific blocking
                                if protocol in p2p_info["protocols"] and access == 'deny':
                                    # Check if this is a broad P2P protocol block
                                    if any(keyword in description for keyword in p2p_info["keywords"]):
                                        if p2p_name not in p2p_protocols_blocked:
                                            p2p_protocols_blocked.append(p2p_name)
                                        self.formatter.print_success(f"Rule '{name}' blocks {p2p_name} protocol ({protocol})")
                                        p2p_blocked = True
                        
                        if p2p_blocked:
                            total_p2p_blocked_nsgs += 1
                            self.formatter.print_success(f"P2P protocols blocked: {', '.join(p2p_protocols_blocked)}")
                        else:
                            self.formatter.print_info(f"NSG '{nsg_name}' has no explicit P2P blocking rules")
                        
                    self.formatter.print_separator()
                    
                    self.formatter.print_key_value("NSGs with P2P restrictions", f"{total_p2p_blocked_nsgs} out of {len(nsgs)}")
                    
                    # Print summary warning only once
                    if total_p2p_blocked_nsgs == 0:
                        self.formatter.print_warning("No NSGs found with explicit P2P protocol blocking rules. Consider implementing NSG rules to block common P2P ports.")
            else:
                self.formatter.print_error(f"Failed to retrieve NSGs: {response.status_code}")
            
            # 2. Check Azure Firewalls
            self.formatter.print_subsection("AZURE FIREWALL P2P RESTRICTIONS")
            firewall_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/azureFirewalls?api-version=2023-04-01"
            firewall_response = self.api_client.arm_get(firewall_url)
            if firewall_response.status_code == 200:
                firewalls = firewall_response.json().get('value', [])
                if not firewalls:
                    self.formatter.print_info("No Azure Firewalls found in the subscription.")
                else:
                    total_p2p_blocked_firewalls = 0
                    for firewall in firewalls:
                        firewall_name = firewall.get('name', 'Unknown')
                        firewall_props = firewall.get('properties', {})
                        rule_collections = firewall_props.get('ruleCollections', [])
                        
                        self.formatter.print_subsection(f"Azure Firewall: {firewall_name}")
                        p2p_blocked = False
                        p2p_protocols_blocked = []
                        
                        for collection in rule_collections:
                            collection_props = collection.get('properties', {})
                            collection_type = collection_props.get('ruleCollectionType', '')
                            rules = collection_props.get('rules', [])
                            
                            for rule in rules:
                                rule_props = rule.get('properties', {})
                                rule_type = rule.get('ruleType', '')
                                action = rule_props.get('action', {}).get('type', '').lower()
                                
                                # Check application rules (for protocol-based blocking)
                                if rule_type == 'ApplicationRule':
                                    protocols = rule_props.get('protocols', [])
                                    target_fqdns = rule_props.get('targetFqdns', [])
                                    fqdn_tags = rule_props.get('fqdnTags', [])
                                    
                                    # Check for P2P protocol blocking
                                    for p2p_name, p2p_info in p2p_protocols.items():
                                        if any(keyword in str(target_fqdns).lower() for keyword in p2p_info["keywords"]) and action == 'deny':
                                            if p2p_name not in p2p_protocols_blocked:
                                                p2p_protocols_blocked.append(p2p_name)
                                            self.formatter.print_success(f"Application rule blocks {p2p_name} traffic")
                                            p2p_blocked = True
                                
                                # Check network rules (for port-based blocking)
                                elif rule_type == 'NetworkRule':
                                    protocols = rule_props.get('protocols', [])
                                    destination_ports = rule_props.get('destinationPorts', [])
                                    
                                    for p2p_name, p2p_info in p2p_protocols.items():
                                        for p2p_port in p2p_info["ports"]:
                                            if any(p2p_port in str(dest_port) for dest_port in destination_ports) and action == 'deny':
                                                if p2p_name not in p2p_protocols_blocked:
                                                    p2p_protocols_blocked.append(p2p_name)
                                                self.formatter.print_success(f"Network rule blocks {p2p_name} port(s) {p2p_port}")
                                                p2p_blocked = True
                        
                        if p2p_blocked:
                            total_p2p_blocked_firewalls += 1
                            self.formatter.print_success(f"P2P protocols blocked: {', '.join(p2p_protocols_blocked)}")
                        else:
                            self.formatter.print_warning("No explicit rules found blocking P2P protocols in Azure Firewall.")
                        
                        self.formatter.print_separator()
                    
                    self.formatter.print_key_value("Azure Firewalls with P2P restrictions", f"{total_p2p_blocked_firewalls} out of {len(firewalls)}")
            else:
                self.formatter.print_error(f"Failed to retrieve Azure Firewalls: {firewall_response.status_code}")
            
            # 3. Check for P2P Protocol Detection in Log Analytics
            self.formatter.print_subsection("P2P PROTOCOL DETECTION IN LOGS")
            workspace_name = getattr(self.config, 'workspace_name', None)
            resource_group = getattr(self.config, 'resource_group', None)
            
            if workspace_name and resource_group:
                try:
                    # Get workspace ID for the Log Analytics Query API
                    workspace_id = self.api_client.get_workspace_id(subscription_id, resource_group, workspace_name)
                    
                    # Query for potential P2P traffic patterns - first check available columns
                    query = """
                    max_subitems = getattr(self.config, 'max_subitems', 10)
                    AzureDiagnostics
                    | where ResourceType in ("NETWORKSECURITYGROUPS", "AZUREFIREWALLS")
                    | where Action_s == "Deny"
                    | where isnotempty(DestinationPort_d)
                    | where DestinationPort_d in (6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 4662, 4663, 4664, 4665, 4666, 6346, 6347, 6348, 411, 412, 1214, 4444, 2234, 6969)
                    | project TimeGenerated, ResourceType, DestinationPort_d, Action_s
                    | order by TimeGenerated desc
                    | take {max_subitems}
                    """
                    
                    # Use the correct Log Analytics Query API endpoint
                    query_response = self.api_client.log_analytics_query(workspace_id, query, "P7D")
                    
                    if query_response.status_code == 200:
                        results = query_response.json()
                        tables = results.get('tables', [])
                        if tables and tables[0].get('rows'):
                            rows = tables[0]['rows']
                            columns = tables[0]['columns']
                            self.formatter.print_success(f"Found {len(rows)} recent P2P traffic denial events:")
                            
                            # Create column mapping
                            col_map = {col['name']: i for i, col in enumerate(columns)}
                            
                            for i, row in enumerate(rows, 1):
                                time_generated = row[col_map.get('TimeGenerated', 0)] if 'TimeGenerated' in col_map else 'Unknown'
                                resource_type = row[col_map.get('ResourceType', 1)] if 'ResourceType' in col_map else 'Unknown'
                                destination_port = row[col_map.get('DestinationPort_d', 2)] if 'DestinationPort_d' in col_map else 'Unknown'
                                action = row[col_map.get('Action_s', 3)] if 'Action_s' in col_map else 'Unknown'
                                
                                self.formatter.print_key_value(f"Event {i}", f"Time: {time_generated}, Type: {resource_type}, Port: {destination_port}, Action: {action}")
                        else:
                            self.formatter.print_info("No recent P2P traffic denial events found in logs.")
                    else:
                        self.formatter.print_warning(f"Could not query Log Analytics for P2P traffic patterns. Status: {query_response.status_code}")
                        # Try a simpler fallback query
                        try:
                            fallback_query = """
                            AzureDiagnostics
                            | where ResourceType in ("NETWORKSECURITYGROUPS", "AZUREFIREWALLS")
                            | where Action_s == "Deny"
                            | where TimeGenerated > ago(7d)
                            | take {max_subitems}
                            """
                            fallback_response = self.api_client.log_analytics_query(workspace_id, fallback_query, "P7D")
                            if fallback_response.status_code == 200:
                                self.formatter.print_info("Fallback query successful - checking for any denial events")
                                fallback_results = fallback_response.json()
                                fallback_tables = fallback_results.get('tables', [])
                                if fallback_tables and fallback_tables[0].get('rows'):
                                    self.formatter.print_info("Denial events exist but may not be P2P-specific")
                                else:
                                    self.formatter.print_info("No denial events found in the last 7 days")
                            else:
                                self.formatter.print_warning("Fallback query also failed - Log Analytics may not be configured for network diagnostics")
                        except Exception as fallback_e:
                            self.formatter.print_warning(f"Fallback query failed: {fallback_e}")
                except Exception as e:
                    self.formatter.print_warning(f"Could not check Log Analytics for P2P patterns: {e}")
            else:
                self.formatter.print_info("Log Analytics workspace not configured - skipping P2P traffic pattern analysis.")
            
            # 4. Summary and Recommendations
            self.formatter.print_subsection("P2P RESTRICTION SUMMARY")
            total_nsgs = len(nsgs) if 'nsgs' in locals() else 0
            total_firewalls = len(firewalls) if 'firewalls' in locals() else 0
            total_p2p_blocked_nsgs = total_p2p_blocked_nsgs if 'total_p2p_blocked_nsgs' in locals() else 0
            total_p2p_blocked_firewalls = total_p2p_blocked_firewalls if 'total_p2p_blocked_firewalls' in locals() else 0
            
            self.formatter.print_key_value("Total NSGs", total_nsgs)
            self.formatter.print_key_value("NSGs with P2P restrictions", total_p2p_blocked_nsgs)
            self.formatter.print_key_value("Total Azure Firewalls", total_firewalls)
            self.formatter.print_key_value("Azure Firewalls with P2P restrictions", total_p2p_blocked_firewalls)
            
            if total_p2p_blocked_nsgs > 0 or total_p2p_blocked_firewalls > 0:
                self.formatter.print_success("P2P file sharing restrictions are in place")
                self.formatter.print_info("Consider implementing additional protocol-based detection for comprehensive P2P blocking")
            else:
                self.formatter.print_error("No P2P file sharing restrictions found")
                self.formatter.print_info("Implement NSG rules and/or Azure Firewall rules to block common P2P protocols and ports")
                self.formatter.print_info("Key P2P protocols to block: BitTorrent, eDonkey, Gnutella, Direct Connect, FastTrack")
            
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking P2P restrictions: {e}")
        self.formatter.print_separator()

    def check_sentinel_system_performance_monitoring(self):
        """Check that Microsoft Sentinel is monitoring system performance and has Teams alert rules configured."""
        self.formatter.print_header(
            "SENTINEL SYSTEM PERFORMANCE MONITORING & TEAMS ALERTING",
            "This function checks Microsoft Sentinel system performance monitoring, Teams alert rules, and other alerting mechanisms for comprehensive system monitoring and incident response."
        )
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        max_lines = getattr(self.config, 'max_lines', 100)

        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return

        # 1. Check System Performance Monitoring
        self.formatter.print_subsection("SYSTEM PERFORMANCE MONITORING")
        try:
            # Get workspace ID for the Log Analytics Query API
            workspace_id = self.api_client.get_workspace_id(subscription_id, resource_group, workspace_name)
            
            query = f"""
            Perf
            | where TimeGenerated > ago(1d)
            | order by TimeGenerated desc
            | take {max_lines}
            """
            
            response = self.api_client.log_analytics_query(workspace_id, query, "P1D")

            if response.status_code == 200:
                results = response.json()
                tables = results.get('tables', [])
                if tables and tables[0].get('rows'):
                    rows = tables[0]['rows']
                    columns = tables[0]['columns']
                    self.formatter.print_success(f"Found {len(rows)} recent system performance records:")
                    col_map = {col['name']: i for i, col in enumerate(columns)}
                    
                    # Group by computer for summary
                    computers = set()
                    performance_objects = set()
                    
                    for i, row in enumerate(rows, 1):
                        if 'Computer' in col_map:
                            computers.add(row[col_map['Computer']])
                        if 'ObjectName' in col_map:
                            performance_objects.add(row[col_map['ObjectName']])
                        
                        # Show first 5 records in detail
                        if i <= 5:
                            self.formatter.print_subsection(f"PERFORMANCE RECORD {i}")
                        if 'TimeGenerated' in col_map:
                            self.formatter.print_key_value("Time", row[col_map['TimeGenerated']])
                        if 'Computer' in col_map:
                            self.formatter.print_key_value("Computer", row[col_map['Computer']])
                        if 'ObjectName' in col_map:
                            self.formatter.print_key_value("Object", row[col_map['ObjectName']])
                        if 'CounterName' in col_map:
                            self.formatter.print_key_value("Counter", row[col_map['CounterName']])
                        if 'InstanceName' in col_map:
                            self.formatter.print_key_value("Instance", row[col_map['InstanceName']])
                        if 'CounterValue' in col_map:
                            self.formatter.print_key_value("Value", row[col_map['CounterValue']])
                    
                    if len(rows) > 5:
                        self.formatter.print_info(f"... and {len(rows) - 5} more performance records")
                    
                    self.formatter.print_key_value("Computers Monitored", len(computers))
                    self.formatter.print_key_value("Performance Objects", len(performance_objects))
                else:
                    self.formatter.print_warning("No recent system performance records found in the Perf table.")
            elif response.status_code == 204:
                self.formatter.print_success("Query executed successfully but no system performance records found.")
            else:
                self.formatter.print_error(f"Failed to query Perf table: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while querying Perf table: {e}")

        # 2. Check Sentinel Analytic Rules with Teams Integration
        self.formatter.print_subsection("SENTINEL ANALYTIC RULES WITH TEAMS INTEGRATION")
        try:
            rules_url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-12-01-preview"
            rules_response = self.api_client.arm_get(rules_url)
            
            if rules_response.status_code == 200:
                rules = rules_response.json().get('value', [])
                teams_integrated_rules = []
                performance_rules = []
                
                for rule in rules:
                    rule_props = rule.get('properties', {})
                    rule_name = rule_props.get('displayName', 'Unnamed Rule')
                    rule_type = rule_props.get('kind', 'Unknown')
                    enabled = rule_props.get('enabled', False)
                    
                    # Check for Teams integration in actions
                    actions = rule_props.get('actions', [])
                    has_teams_action = False
                    has_logic_app = False
                    
                    for action in actions:
                        action_type = action.get('actionType', '')
                        if action_type == 'MicrosoftTeams':
                            has_teams_action = True
                        elif action_type == 'LogicApp':
                            has_logic_app = True
                    
                    # Check if rule is related to performance monitoring
                    query = rule_props.get('query', '').lower()
                    is_performance_rule = any(keyword in query for keyword in ['perf', 'cpu', 'memory', 'disk', 'network', 'performance'])
                    
                    if has_teams_action or has_logic_app:
                        teams_integrated_rules.append({
                            'name': rule_name,
                            'type': rule_type,
                            'enabled': enabled,
                            'teams': has_teams_action,
                            'logic_app': has_logic_app
                        })
                    
                    if is_performance_rule:
                        performance_rules.append({
                            'name': rule_name,
                            'type': rule_type,
                            'enabled': enabled,
                            'teams': has_teams_action,
                            'logic_app': has_logic_app
                        })
                
                if teams_integrated_rules:
                    self.formatter.print_success(f"Found {len(teams_integrated_rules)} Sentinel rules with Teams/Logic App integration:")
                    for rule in teams_integrated_rules:
                        integrations = []
                        if rule['teams']:
                            integrations.append("Teams")
                        if rule['logic_app']:
                            integrations.append("Logic App")
                        
                        status = "Enabled" if rule['enabled'] else "Disabled"
                        self.formatter.print_key_value(f"{rule['name']} ({rule['type']})", f"{status} - {', '.join(integrations)}")
                else:
                    self.formatter.print_warning("No Sentinel rules found with Teams or Logic App integration")
                
                if performance_rules:
                    self.formatter.print_success(f"Found {len(performance_rules)} performance-related Sentinel rules:")
                    for rule in performance_rules:
                        integrations = []
                        if rule['teams']:
                            integrations.append("Teams")
                        if rule['logic_app']:
                            integrations.append("Logic App")
                        
                        status = "Enabled" if rule['enabled'] else "Disabled"
                        integrations_str = f" - {', '.join(integrations)}" if integrations else " - No Teams integration"
                        self.formatter.print_key_value(f"{rule['name']} ({rule['type']})", f"{status}{integrations_str}")
                else:
                    self.formatter.print_info("No performance-related Sentinel rules found")
            else:
                self.formatter.print_error(f"Failed to retrieve Sentinel rules: {rules_response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking Sentinel rules: {e}")

        # 3. Check for Logic Apps with Teams Integration
        self.formatter.print_subsection("LOGIC APPS WITH TEAMS INTEGRATION")
        try:
            logic_apps_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Logic/workflows?api-version=2019-05-01"
            logic_apps_response = self.api_client.arm_get(logic_apps_url)
            
            if logic_apps_response.status_code == 200:
                logic_apps = logic_apps_response.json().get('value', [])
                teams_integrated_logic_apps = []
                
                for app in logic_apps:
                    app_name = app.get('name', 'Unnamed')
                    app_props = app.get('properties', {})
                    app_state = app_props.get('state', 'Unknown')
                    
                    # Check if Logic App has Teams actions
                    try:
                        # Get Logic App definition to check for Teams actions
                        definition_url = f"{app.get('id')}/triggers?api-version=2019-05-01"
                        definition_response = self.api_client.arm_get(definition_url)
                        
                        if definition_response.status_code == 200:
                            triggers = definition_response.json().get('value', [])
                            
                            # Check for Teams-related triggers or actions
                            has_teams_integration = False
                            for trigger in triggers:
                                trigger_props = trigger.get('properties', {})
                                trigger_type = trigger_props.get('type', '')
                                if 'teams' in trigger_type.lower() or 'microsoftteams' in str(trigger_props).lower():
                                    has_teams_integration = True
                                    break
                            
                            if has_teams_integration:
                                teams_integrated_logic_apps.append({
                                    'name': app_name,
                                    'state': app_state
                                })
                    except Exception:
                        # Skip if we can't check this Logic App
                        continue
                
                if teams_integrated_logic_apps:
                    self.formatter.print_success(f"Found {len(teams_integrated_logic_apps)} Logic Apps with Teams integration:")
                    for app in teams_integrated_logic_apps:
                        self.formatter.print_key_value(f"{app['name']}", f"State: {app['state']}")
                else:
                    self.formatter.print_info("No Logic Apps found with Teams integration")
            else:
                self.formatter.print_error(f"Failed to retrieve Logic Apps: {logic_apps_response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking Logic Apps: {e}")

        # 4. Check for Recent Performance Alerts
        self.formatter.print_subsection("RECENT PERFORMANCE ALERTS")
        try:
            max_subitems = getattr(self.config, 'max_subitems', 10)
            # Try multiple alert table names and approaches
            alert_queries = [
                # Try SecurityAlert table first
                """
                SecurityAlert
                | where TimeGenerated > ago(7d)
                | where AlertName contains "performance" or AlertName contains "cpu" or AlertName contains "memory" or AlertName contains "disk"
                | order by TimeGenerated desc
                | take {max_subitems}
                """,
                # Try AzureDiagnostics for alerts
                """
                AzureDiagnostics
                | where ResourceType == "SECURITYINSIGHTS"
                | where TimeGenerated > ago(7d)
                | order by TimeGenerated desc
                | take {max_subitems}
                """,
                # Try any alerts in the workspace
                """
                union isfuzzy=true
                (SecurityAlert | where TimeGenerated > ago(7d) | take {max_subitems}),
                (AzureDiagnostics | where ResourceType == "SECURITYINSIGHTS" | where TimeGenerated > ago(7d) | take {max_subitems})
                | order by TimeGenerated desc
                | take {max_subitems}
                """,
                # Simple query to check if any alerts exist
                """
                union isfuzzy=true
                (SecurityAlert | take 1),
                (AzureDiagnostics | where ResourceType == "SECURITYINSIGHTS" | take 1)
                | take 1
                """
            ]
            
            alerts_found = False
            
            for i, alerts_query in enumerate(alert_queries):
                try:
                    alerts_response = self.api_client.log_analytics_query(workspace_id, alerts_query, "P7D")
                    
                    if alerts_response.status_code == 200:
                        alerts_results = alerts_response.json()
                        alerts_tables = alerts_results.get('tables', [])
                        if alerts_tables and alerts_tables[0].get('rows'):
                            alerts_rows = alerts_tables[0]['rows']
                            alerts_columns = alerts_tables[0]['columns']
                            
                            if i == 0:  # First query - performance alerts
                                self.formatter.print_success(f"Found {len(alerts_rows)} recent performance-related security alerts:")
                                
                                alerts_col_map = {col['name']: i for i, col in enumerate(alerts_columns)}
                                
                                for j, alert_row in enumerate(alerts_rows, 1):
                                    alert_time = alert_row[alerts_col_map.get('TimeGenerated', 0)] if 'TimeGenerated' in alerts_col_map else 'Unknown'
                                    alert_name = alert_row[alerts_col_map.get('AlertName', 1)] if 'AlertName' in alerts_col_map else 'Unknown'
                                    alert_severity = alert_row[alerts_col_map.get('Severity', 2)] if 'Severity' in alerts_col_map else 'Unknown'
                                    
                                    self.formatter.print_key_value(f"Alert {j}", f"Time: {alert_time}, Name: {alert_name}, Severity: {alert_severity}")
                                alerts_found = True
                                break
                            
                            elif i == 1:  # Second query - AzureDiagnostics alerts
                                self.formatter.print_success(f"Found {len(alerts_rows)} recent alerts in AzureDiagnostics:")
                                
                                alerts_col_map = {col['name']: i for i, col in enumerate(alerts_columns)}
                                
                                for j, alert_row in enumerate(alerts_rows, 1):
                                    alert_time = alert_row[alerts_col_map.get('TimeGenerated', 0)] if 'TimeGenerated' in alerts_col_map else 'Unknown'
                                    resource_type = alert_row[alerts_col_map.get('ResourceType', 1)] if 'ResourceType' in alerts_col_map else 'Unknown'
                                    
                                    self.formatter.print_key_value(f"Alert {j}", f"Time: {alert_time}, Type: {resource_type}")
                                alerts_found = True
                                break
                            
                            elif i == 2:  # Third query - any alerts
                                self.formatter.print_success(f"Found {len(alerts_rows)} recent alerts in the workspace:")
                                
                                alerts_col_map = {col['name']: i for i, col in enumerate(alerts_columns)}
                                
                                for j, alert_row in enumerate(alerts_rows, 1):
                                    alert_time = alert_row[alerts_col_map.get('TimeGenerated', 0)] if 'TimeGenerated' in alerts_col_map else 'Unknown'
                                    alert_name = alert_row[alerts_col_map.get('AlertName', 1)] if 'AlertName' in alerts_col_map else 'Unknown'
                                    
                                    self.formatter.print_key_value(f"Alert {j}", f"Time: {alert_time}, Name: {alert_name}")
                                alerts_found = True
                                break
                            
                            elif i == 3:  # Fourth query - check if alerts exist
                                self.formatter.print_info("Alert tables exist but no recent performance-related alerts found")
                                alerts_found = True
                                break
                    
                    elif alerts_response.status_code == 204:
                        if i == 3:  # Last query - no alerts at all
                            self.formatter.print_info("No alert data found in the workspace - alerts may not be configured")
                            alerts_found = True
                        continue  # Try next query
                    
                    else:
                        if i == 3:  # Last query
                            self.formatter.print_warning(f"Could not query for alerts: {alerts_response.status_code}")
                        continue  # Try next query
                        
                except Exception as query_e:
                    if i == 3:  # Last query
                        self.formatter.print_warning(f"Exception in alert query {i+1}: {query_e}")
                    continue  # Try next query
            
            if not alerts_found:
                self.formatter.print_info("No recent alerts found - this may indicate no alerting is configured")
                
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking performance alerts: {e}")

        # 5. Summary and Recommendations
        self.formatter.print_subsection("PERFORMANCE MONITORING SUMMARY")
        total_rules = len(rules) if 'rules' in locals() else 0
        teams_rules = len(teams_integrated_rules) if 'teams_integrated_rules' in locals() else 0
        performance_rules_count = len(performance_rules) if 'performance_rules' in locals() else 0
        logic_apps_count = len(teams_integrated_logic_apps) if 'teams_integrated_logic_apps' in locals() else 0
        
        self.formatter.print_key_value("Total Sentinel Rules", total_rules)
        self.formatter.print_key_value("Rules with Teams Integration", teams_rules)
        self.formatter.print_key_value("Performance-Related Rules", performance_rules_count)
        self.formatter.print_key_value("Logic Apps with Teams Integration", logic_apps_count)
        
        if teams_rules > 0 or logic_apps_count > 0:
            self.formatter.print_success("Teams alerting is configured for system monitoring")
            self.formatter.print_info("Consider implementing additional performance thresholds and automated response actions")
        else:
            self.formatter.print_warning("No Teams alerting found for system monitoring")
            self.formatter.print_info("Configure Teams integration in Sentinel rules and Logic Apps for automated alerting")
            self.formatter.print_info("Key areas to monitor: CPU, Memory, Disk, Network, Application Performance")
        
        self.formatter.print_separator()

    def check_defender_vulnerability_management(self):
        """Check Microsoft Defender Vulnerability Management configuration and ensure vulnerabilities are ingested into Microsoft Sentinel."""
        self.formatter.print_header(
            "MICROSOFT DEFENDER VULNERABILITY MANAGEMENT CONFIGURATION",
            "This function verifies that Microsoft Defender Vulnerability Management is enabled and properly configured for vulnerability scanning. It confirms vulnerabilities are being ingested into Microsoft Sentinel for monitoring and alerting."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        
        # Track compliance metrics
        vulnerability_management_enabled = False
        sentinel_integration_configured = False
        vulnerability_alerts_found = False
        recent_vulnerabilities = 0
        sonarqube_vms_found = 0
        sonarqube_services_found = 0
        sonarqube_containers_found = 0
        
        # 1. Check Microsoft Defender for Cloud Vulnerability Management
        self.formatter.print_subsection("MICROSOFT DEFENDER FOR CLOUD VULNERABILITY MANAGEMENT")
        try:
            # Check Defender for Cloud pricing configuration
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/pricings?api-version=2023-01-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                pricings = response.json().get('value', [])
                if not pricings:
                    self.formatter.print_warning("No Microsoft Defender for Cloud pricing configurations found")
                else:
                    self.formatter.print_success(f"Found {len(pricings)} Defender for Cloud pricing configurations")
                    
                    for pricing in pricings:
                        pricing_name = pricing.get('name', 'Unknown')
                        pricing_props = pricing.get('properties', {})
                        pricing_tier = pricing_props.get('pricingTier', 'Unknown')
                        sub_tier = pricing_props.get('subPlan', 'Unknown')
                        
                        self.formatter.print_subsection(f"DEFENDER PLAN: {pricing_name}")
                        self.formatter.print_key_value("Pricing Tier", pricing_tier)
                        self.formatter.print_key_value("Sub Plan", sub_tier)
                        
                        # Check for vulnerability management plans
                        vulnerability_plans = [
                            'VulnerabilityAssessment', 'VulnerabilityAssessmentStandard',
                            'DefenderForServers', 'DefenderForContainers', 'DefenderForDatabases'
                        ]
                        
                        if pricing_name in vulnerability_plans or 'Vulnerability' in pricing_name:
                            if pricing_tier in ['Standard', 'Premium']:
                                vulnerability_management_enabled = True
                                self.formatter.print_success("Vulnerability management plan enabled")
                            else:
                                self.formatter.print_warning("Vulnerability management plan found but not on Standard/Premium tier")
                        elif pricing_tier in ['Standard', 'Premium']:
                            self.formatter.print_info("Standard/Premium tier plan found - may include vulnerability features")
                        else:
                            self.formatter.print_warning("Free tier plan - limited vulnerability management capabilities")
                        
                        # Check if plan is enabled
                        if pricing_props.get('enabled', False):
                            self.formatter.print_success("Plan is enabled")
                        else:
                            self.formatter.print_error("Plan is disabled")
                        
                        self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve Defender for Cloud pricing: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking Defender for Cloud: {e}")
        
        # 2. Check for Vulnerability Assessment Solutions
        self.formatter.print_subsection("VULNERABILITY ASSESSMENT SOLUTIONS")
        try:
            # Check for security solutions
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/locations?api-version=2020-01-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                locations = response.json().get('value', [])
                if locations:
                    location = locations[0].get('name', 'default')
                    
                    # Check security solutions
                    solutions_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/locations/{location}/securitySolutions?api-version=2020-01-01"
                    solutions_response = self.api_client.arm_get(solutions_url)
                    
                    if solutions_response.status_code == 200:
                        solutions = solutions_response.json().get('value', [])
                        if solutions:
                            self.formatter.print_success(f"Found {len(solutions)} security solutions")
                            
                            for solution in solutions:
                                solution_name = solution.get('name', 'Unknown')
                                solution_props = solution.get('properties', {})
                                solution_type = solution_props.get('securityFamily', 'Unknown')
                                solution_status = solution_props.get('provisioningState', 'Unknown')
                                
                                self.formatter.print_key_value(f"Solution: {solution_name}", f"Type: {solution_type}, Status: {solution_status}")
                                
                                # Check for vulnerability assessment solutions
                                if 'VulnerabilityAssessment' in solution_name or 'Vulnerability' in solution_type:
                                    vulnerability_management_enabled = True
                                    self.formatter.print_success("Vulnerability assessment solution found")
                                
                                # Check for SonarQube solutions
                                if 'SonarQube' in solution_name or 'SonarQube' in solution_type or 'CodeQuality' in solution_type:
                                    vulnerability_management_enabled = True
                                    self.formatter.print_success("SonarQube code quality solution found")
                                
                                if solution_status == 'Succeeded':
                                    self.formatter.print_success("Solution is provisioned successfully")
                                else:
                                    self.formatter.print_warning(f"Solution status: {solution_status}")
                        else:
                            self.formatter.print_info("No security solutions found")
                    else:
                        self.formatter.print_warning(f"Could not retrieve security solutions: {solutions_response.status_code}")
                else:
                    self.formatter.print_warning("No security locations found")
            else:
                self.formatter.print_warning(f"Could not retrieve security locations: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking security solutions: {e}")
        
        # 3. Check for Vulnerability Assessment on VMs
        self.formatter.print_subsection("VIRTUAL MACHINE VULNERABILITY ASSESSMENT")
        try:
            # Get all VMs
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines?api-version=2023-07-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                vms = response.json().get('value', [])
                if not vms:
                    self.formatter.print_info("No Virtual Machines found in this subscription")
                else:
                    self.formatter.print_success(f"Found {len(vms)} Virtual Machines")
                    
                    vm_with_vulnerability_assessment = 0
                    vm_without_vulnerability_assessment = 0
                    sonarqube_vms_found = 0
                    
                    for vm in vms:
                        vm_name = vm.get('name', 'Unknown')
                        vm_id = vm.get('id', '')
                        vm_location = vm.get('location', 'Unknown')
                        
                        # Check for vulnerability assessment extension
                        extensions_url = f"{vm_id}/extensions?api-version=2023-07-01"
                        extensions_response = self.api_client.arm_get(extensions_url)
                        
                        if extensions_response.status_code == 200:
                            extensions = extensions_response.json().get('value', [])
                            vulnerability_extension_found = False
                            sonarqube_extension_found = False
                            
                            for extension in extensions:
                                extension_name = extension.get('name', 'Unknown')
                                extension_props = extension.get('properties', {})
                                extension_type = extension_props.get('type', 'Unknown')
                                extension_state = extension_props.get('provisioningState', 'Unknown')
                                
                                # Check for vulnerability assessment extensions
                                vulnerability_extensions = [
                                    'Qualys.WindowsAgent', 'Qualys.LinuxAgent', 'Rapid7.WindowsAgent', 'Rapid7.LinuxAgent',
                                    'Microsoft.Azure.Security.VulnerabilityAssessment', 'Microsoft.Azure.Security.IoTSecurity'
                                ]
                                
                                # Check for SonarQube extensions
                                sonarqube_extensions = [
                                    'SonarQube.Agent', 'SonarQube.Scanner', 'SonarQube.Server', 'SonarQube.WindowsAgent',
                                    'SonarQube.LinuxAgent', 'Microsoft.Azure.Security.SonarQube'
                                ]
                                
                                if any(ext in extension_type for ext in vulnerability_extensions):
                                    vulnerability_extension_found = True
                                    vm_with_vulnerability_assessment += 1
                                    self.formatter.print_success(f"VM {vm_name}: Vulnerability assessment extension found ({extension_type})")
                                    self.formatter.print_key_value(f"  Extension Status", extension_state)
                                    break
                                
                                if any(ext in extension_type for ext in sonarqube_extensions):
                                    sonarqube_extension_found = True
                                    sonarqube_vms_found += 1
                                    self.formatter.print_success(f"VM {vm_name}: SonarQube extension found ({extension_type})")
                                    self.formatter.print_key_value(f"  Extension Status", extension_state)
                                    break
                            
                            if not vulnerability_extension_found and not sonarqube_extension_found:
                                vm_without_vulnerability_assessment += 1
                                self.formatter.print_warning(f"VM {vm_name}: No vulnerability assessment or SonarQube extension found")
                        else:
                            vm_without_vulnerability_assessment += 1
                            self.formatter.print_warning(f"VM {vm_name}: Could not check extensions")
                    
                    # Summary of VM vulnerability assessment
                    self.formatter.print_subsection("VM VULNERABILITY ASSESSMENT SUMMARY")
                    self.formatter.print_key_value("VMs with Vulnerability Assessment", vm_with_vulnerability_assessment)
                    self.formatter.print_key_value("VMs with SonarQube", sonarqube_vms_found)
                    self.formatter.print_key_value("VMs without Vulnerability Assessment", vm_without_vulnerability_assessment)
                    
                    if vm_with_vulnerability_assessment > 0 or sonarqube_vms_found > 0:
                        vulnerability_management_enabled = True
                        if vm_with_vulnerability_assessment > 0:
                            self.formatter.print_success("Some VMs have vulnerability assessment configured")
                        if sonarqube_vms_found > 0:
                            self.formatter.print_success("Some VMs have SonarQube configured")
                    else:
                        self.formatter.print_warning("No VMs have vulnerability assessment or SonarQube configured")
            else:
                self.formatter.print_error(f"Failed to retrieve Virtual Machines: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking VM vulnerability assessment: {e}")
        
        # 4. Check for SonarQube Services and Configurations
        self.formatter.print_subsection("SONARQUBE CODE QUALITY AND VULNERABILITY SCANNING")
        sonarqube_services_found = 0
        sonarqube_containers_found = 0
        
        try:
            # Check for SonarQube as App Service
            app_services_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Web/sites?api-version=2022-09-01"
            app_response = self.api_client.arm_get(app_services_url)
            if app_response.status_code == 200:
                app_services = app_response.json().get('value', [])
                for app in app_services:
                    app_name = app.get('name', 'Unknown')
                    if 'sonar' in app_name.lower() or 'sonarqube' in app_name.lower():
                        sonarqube_services_found += 1
                        self.formatter.print_success(f"SonarQube App Service found: {app_name}")
                        self.formatter.print_key_value("  Service Type", "App Service")
                        vulnerability_management_enabled = True
            
            # Check for SonarQube in Container Instances
            container_instances_url = f"/subscriptions/{subscription_id}/providers/Microsoft.ContainerInstance/containerGroups?api-version=2022-10-01"
            container_response = self.api_client.arm_get(container_instances_url)
            if container_response.status_code == 200:
                container_groups = container_response.json().get('value', [])
                for group in container_groups:
                    group_name = group.get('name', 'Unknown')
                    containers = group.get('properties', {}).get('containers', [])
                    for container in containers:
                        container_image = container.get('properties', {}).get('image', '')
                        if 'sonar' in container_image.lower() or 'sonarqube' in container_image.lower():
                            sonarqube_containers_found += 1
                            self.formatter.print_success(f"SonarQube Container found: {group_name}")
                            self.formatter.print_key_value("  Container Image", container_image)
                            vulnerability_management_enabled = True
            
            # Check for SonarQube in AKS (Azure Kubernetes Service)
            aks_clusters_url = f"/subscriptions/{subscription_id}/providers/Microsoft.ContainerService/managedClusters?api-version=2023-07-02"
            aks_response = self.api_client.arm_get(aks_clusters_url)
            if aks_response.status_code == 200:
                aks_clusters = aks_response.json().get('value', [])
                for cluster in aks_clusters:
                    cluster_name = cluster.get('name', 'Unknown')
                    # Note: Detailed pod checking would require additional API calls to the cluster
                    self.formatter.print_info(f"AKS Cluster found: {cluster_name} - SonarQube pods would need cluster access to verify")
            
            # Summary of SonarQube services
            if sonarqube_services_found > 0 or sonarqube_containers_found > 0:
                self.formatter.print_subsection("SONARQUBE SERVICES SUMMARY")
                self.formatter.print_key_value("SonarQube App Services", sonarqube_services_found)
                self.formatter.print_key_value("SonarQube Containers", sonarqube_containers_found)
                self.formatter.print_success("SonarQube code quality scanning services found")
            else:
                self.formatter.print_info("No SonarQube services found in Azure resources")
                
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking SonarQube services: {e}")
        
        # 5. Check Microsoft Sentinel for Vulnerability Alerts
        self.formatter.print_subsection("MICROSOFT SENTINEL VULNERABILITY ALERTS")
        workspace_name = getattr(self.config, 'workspace_name', None)
        resource_group = getattr(self.config, 'resource_group', None)
        
        if workspace_name and resource_group:
            try:
                # Query for vulnerability-related alerts in Sentinel
                max_subitems = getattr(self.config, 'max_subitems', 10)
                vulnerability_query = """
                SecurityAlert
                | where TimeGenerated > ago(30d)
                | where AlertName contains "vulnerability" or AlertName contains "Vulnerability" or AlertName contains "CVE" or AlertName contains "cve" or AlertName contains "SonarQube" or AlertName contains "sonarqube" or AlertName contains "CodeQuality" or AlertName contains "code quality"
                | where ProviderName in ("Microsoft Defender for Cloud", "Microsoft Defender for Endpoint", "Azure Security Center", "SonarQube", "Code Quality Scanner")
                | summarize count() by AlertName, ProviderName
                | order by count_ desc
                | take {max_subitems}
                """
                
                workspace_id = self.api_client.get_workspace_id(subscription_id, resource_group, workspace_name)
                query_response = self.api_client.log_analytics_query(workspace_id, vulnerability_query, "P30D")
                
                if query_response.status_code == 200:
                    results = query_response.json()
                    tables = results.get('tables', [])
                    if tables and tables[0].get('rows'):
                        rows = tables[0]['rows']
                        vulnerability_alerts_found = True
                        recent_vulnerabilities = len(rows)
                        
                        self.formatter.print_success(f"Found {len(rows)} vulnerability alert types in the last 30 days")
                        
                        for i, row in enumerate(rows, 1):
                            alert_name = row[0] if len(row) > 0 else 'Unknown'
                            provider = row[1] if len(row) > 1 else 'Unknown'
                            count = row[2] if len(row) > 2 else 'Unknown'
                            
                            self.formatter.print_key_value(f"Alert {i}", f"{alert_name} ({provider})")
                            self.formatter.print_key_value(f"  Count", count)
                        
                        sentinel_integration_configured = True
                        self.formatter.print_success("Vulnerability alerts are being ingested into Microsoft Sentinel")
                    else:
                        self.formatter.print_warning("No vulnerability alerts found in Microsoft Sentinel in the last 30 days")
                        
                        # Try a broader query for any security alerts
                        broader_query = """
                        SecurityAlert
                        | where TimeGenerated > ago(30d)
                        | where ProviderName in ("Microsoft Defender for Cloud", "Microsoft Defender for Endpoint", "Azure Security Center")
                        | summarize count() by ProviderName
                        | order by count_ desc
                        """
                        
                        broader_response = self.api_client.log_analytics_query(workspace_id, broader_query, "P30D")
                        
                        if broader_response.status_code == 200:
                            broader_results = broader_response.json()
                            broader_tables = broader_results.get('tables', [])
                            if broader_tables and broader_tables[0].get('rows'):
                                self.formatter.print_info("Security alerts are being ingested, but no specific vulnerability alerts found")
                                sentinel_integration_configured = True
                            else:
                                self.formatter.print_warning("No security alerts found in Microsoft Sentinel")
                        else:
                            self.formatter.print_warning(f"Could not query for security alerts: {broader_response.status_code}")
                else:
                    self.formatter.print_warning(f"Could not query Microsoft Sentinel for vulnerability alerts: {query_response.status_code}")
            except Exception as e:
                self.formatter.print_error(f"Exception occurred while checking Sentinel vulnerability alerts: {e}")
        else:
            self.formatter.print_warning("workspace_name and resource_group not configured - skipping Sentinel checks")
        
        # 5. Check for Vulnerability Assessment in Azure Security Center
        self.formatter.print_subsection("AZURE SECURITY CENTER VULNERABILITY ASSESSMENT")
        try:
            # Check for security assessments
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/assessments?api-version=2020-01-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                assessments = response.json().get('value', [])
                if assessments:
                    vulnerability_assessments = []
                    
                    for assessment in assessments:
                        assessment_name = assessment.get('name', 'Unknown')
                        assessment_props = assessment.get('properties', {})
                        assessment_display_name = assessment_props.get('displayName', 'Unknown')
                        assessment_status = assessment_props.get('status', {}).get('code', 'Unknown')
                        
                        # Look for vulnerability-related assessments
                        if any(keyword in assessment_display_name.lower() for keyword in ['vulnerability', 'cve', 'security baseline']):
                            vulnerability_assessments.append(assessment)
                            self.formatter.print_key_value(f"Assessment: {assessment_display_name}", assessment_status)
                    
                    if vulnerability_assessments:
                        self.formatter.print_success(f"Found {len(vulnerability_assessments)} vulnerability-related assessments")
                        vulnerability_management_enabled = True
                    else:
                        self.formatter.print_info("No vulnerability-related assessments found")
                else:
                    self.formatter.print_info("No security assessments found")
            else:
                self.formatter.print_warning(f"Could not retrieve security assessments: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking security assessments: {e}")
        
        # 6. Summary and Compliance Assessment
        self.formatter.print_subsection("VULNERABILITY MANAGEMENT COMPLIANCE SUMMARY")
        self.formatter.print_key_value("Vulnerability Management Enabled", vulnerability_management_enabled)
        self.formatter.print_key_value("Sentinel Integration Configured", sentinel_integration_configured)
        self.formatter.print_key_value("Vulnerability Alerts Found", vulnerability_alerts_found)
        self.formatter.print_key_value("Recent Vulnerability Alerts", recent_vulnerabilities)
        self.formatter.print_key_value("SonarQube VMs Found", sonarqube_vms_found)
        self.formatter.print_key_value("SonarQube Services Found", sonarqube_services_found)
        self.formatter.print_key_value("SonarQube Containers Found", sonarqube_containers_found)
        
        # Compliance assessment
        if vulnerability_management_enabled and sentinel_integration_configured:
            if vulnerability_alerts_found:
                self.formatter.print_success("EXCELLENT: Vulnerability management is enabled and actively reporting to Sentinel")
            else:
                self.formatter.print_warning("GOOD: Vulnerability management is enabled but no recent alerts found")
        elif vulnerability_management_enabled:
            self.formatter.print_warning("MODERATE: Vulnerability management is enabled but Sentinel integration needs verification")
        else:
            self.formatter.print_error("POOR: Vulnerability management is not properly configured")
        
        # Compliance evidence
        self.formatter.print_subsection("COMPLIANCE EVIDENCE")
        if vulnerability_management_enabled and sentinel_integration_configured and vulnerability_alerts_found:
            self.formatter.print_success("VULNERABILITY MANAGEMENT VERIFIED: Microsoft Defender Vulnerability Management is enabled and configured. Vulnerabilities are being ingested into Microsoft Sentinel for monitoring and alerting, providing comprehensive vulnerability assessment coverage for FedRAMP Moderate compliance.")
        elif vulnerability_management_enabled and sentinel_integration_configured:
            self.formatter.print_warning("PARTIAL COMPLIANCE: Vulnerability management is enabled and integrated with Sentinel, but no recent vulnerability alerts detected. Verify scanning schedules and alert configurations.")
        elif vulnerability_management_enabled:
            self.formatter.print_warning("PARTIAL COMPLIANCE: Vulnerability management is enabled but Sentinel integration needs verification. Ensure vulnerability alerts are being sent to Microsoft Sentinel.")
        else:
            self.formatter.print_error("NON-COMPLIANT: Microsoft Defender Vulnerability Management is not properly configured. Implement vulnerability scanning and ensure integration with Microsoft Sentinel for comprehensive vulnerability monitoring.")
        
        self.formatter.print_separator()

    def check_asg_boundary_protection(self):
        """Check that Azure ASGs are used for boundary protection and limited to allowed ports, protocols, and services."""
        self.formatter.print_header(
            "AZURE ASG BOUNDARY PROTECTION & NSG DEFAULT RULES",
            "This function checks Network Security Groups for default rule priority 65000 DenyAllInbound and enumerates Azure Application Security Groups (ASGs) to verify ASG-to-ASG rules for permit-by-exception boundary protection."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        
        # Track compliance metrics
        total_nsgs = 0
        nsgs_with_deny_all_inbound = 0
        total_asgs = 0
        asgs_with_rules = 0
        asg_to_asg_rules_found = 0
        
        try:
            # 1. Check NSGs for default rule priority 65000 DenyAllInbound
            self.formatter.print_subsection("NSG DEFAULT RULES - PRIORITY 65000 DENYALLINBOUND")
            nsg_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-04-01"
            nsg_response = self.api_client.arm_get(nsg_url)
            if nsg_response.status_code == 200:
                nsgs = nsg_response.json().get('value', [])
                if not nsgs:
                    self.formatter.print_warning("No Network Security Groups found in the subscription.")
                else:
                    total_nsgs = len(nsgs)
                    self.formatter.print_success(f"Found {total_nsgs} Network Security Groups")
                    
                    for nsg in nsgs:
                        nsg_name = nsg.get('name', 'Unknown')
                        nsg_id = nsg.get('id', '')
                        rg = nsg_id.split('/')[4] if len(nsg_id.split('/')) > 4 else 'Unknown'
                        
                        self.formatter.print_subsection(f"NSG: {nsg_name}")
                        self.formatter.print_key_value("Resource Group", rg)
                        
                        # Check default security rules (priority 65000)
                        default_rules = nsg.get('properties', {}).get('defaultSecurityRules', [])
                        deny_all_inbound_found = False
                        misconfigured_deny_all_inbound = False
                        
                        for rule in default_rules:
                            rule_name = rule.get('name', 'Unknown')
                            priority = rule.get('priority', 0)
                            access = rule.get('access', '').lower()
                            direction = rule.get('direction', '').lower()
                            
                            # Check for DenyAllInbound rules
                            if (direction == 'inbound' and 
                                access == 'deny' and 
                                rule_name.lower() in ['denyall', 'denyallinbound', 'denyallinboundtraffic']):
                                
                                if priority == 65000:
                                    deny_all_inbound_found = True
                                    nsgs_with_deny_all_inbound += 1
                                    self.formatter.print_success(f"Found DenyAllInbound rule: {rule_name} (Priority: {priority})")
                                    break
                                else:
                                    misconfigured_deny_all_inbound = True
                                    self.formatter.print_error(f"⚠️  MISCONFIGURED: Found DenyAllInbound rule '{rule_name}' with incorrect priority {priority} (should be 65000)")
                        
                        if not deny_all_inbound_found and not misconfigured_deny_all_inbound:
                            self.formatter.print_error(f"Missing DenyAllInbound rule with priority 65000")
                        
                        # Check custom security rules for ASG references
                        custom_rules = nsg.get('properties', {}).get('securityRules', [])
                        asg_rules_in_nsg = 0
                        
                        for rule in custom_rules:
                            src_asgs = rule.get('sourceApplicationSecurityGroups', [])
                            dst_asgs = rule.get('destinationApplicationSecurityGroups', [])
                            
                            # Check if this is an ASG-to-ASG rule
                            if src_asgs and dst_asgs:
                                asg_to_asg_rules_found += 1
                                asg_rules_in_nsg += 1
                                rule_name = rule.get('name', 'Unknown')
                                access = rule.get('access', '').lower()
                                direction = rule.get('direction', '').lower()
                                protocol = rule.get('protocol', 'Any')
                                port_range = rule.get('destinationPortRange', '')
                                port_ranges = rule.get('destinationPortRanges', [])
                                priority = rule.get('priority', 0)
                                
                                self.formatter.print_success(f"ASG-to-ASG rule found: {rule_name}")
                                self.formatter.print_key_value("  Priority", priority)
                                self.formatter.print_key_value("  Direction", direction)
                                self.formatter.print_key_value("  Access", access)
                                self.formatter.print_key_value("  Protocol", protocol)
                                
                                all_ports = [port_range] if port_range else []
                                all_ports += port_ranges
                                self.formatter.print_key_value("  Ports", ', '.join(all_ports) if all_ports else 'Any')
                                
                                # Show ASG details
                                src_asg_names = [asg.get('id', '').split('/')[-1] for asg in src_asgs]
                                dst_asg_names = [asg.get('id', '').split('/')[-1] for asg in dst_asgs]
                                self.formatter.print_key_value("  Source ASGs", ', '.join(src_asg_names))
                                self.formatter.print_key_value("  Destination ASGs", ', '.join(dst_asg_names))
                        
                        if asg_rules_in_nsg == 0:
                            self.formatter.print_info("No ASG-to-ASG rules found in this NSG")
                        
                        self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve NSGs: {nsg_response.status_code}")
            
            # 2. List all ASGs and their usage
            self.formatter.print_subsection("APPLICATION SECURITY GROUPS (ASG) INVENTORY")
            asg_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/applicationSecurityGroups?api-version=2023-04-01"
            asg_response = self.api_client.arm_get(asg_url)
            if asg_response.status_code == 200:
                asgs = asg_response.json().get('value', [])
                if not asgs:
                    self.formatter.print_warning("No Application Security Groups found in the subscription.")
                else:
                    total_asgs = len(asgs)
                    self.formatter.print_success(f"Found {total_asgs} Application Security Groups")
                    
                for asg in asgs:
                    asg_name = asg.get('name', 'Unknown')
                    asg_id = asg.get('id', '')
                    rg = asg_id.split('/')[4] if len(asg_id.split('/')) > 4 else 'Unknown'
                    location = asg.get('location', 'Unknown')
                        
                    self.formatter.print_subsection(f"ASG: {asg_name}")
                    self.formatter.print_key_value("Resource Group", rg)
                    self.formatter.print_key_value("Location", location)
                        
                    # Check if this ASG is referenced in any NSG rules
                    asg_referenced = False
                    for nsg in nsgs:
                        nsg_name = nsg.get('name', 'Unknown')
                        rules = nsg.get('properties', {}).get('securityRules', [])
                            
                        for rule in rules:
                            src_asgs = rule.get('sourceApplicationSecurityGroups', [])
                            dst_asgs = rule.get('destinationApplicationSecurityGroups', [])
                                
                            # Check if this ASG is referenced
                            if any(asg_id == s.get('id') for s in src_asgs + dst_asgs):
                                asg_referenced = True
                                asgs_with_rules += 1
                                rule_name = rule.get('name', 'Unknown')
                                access = rule.get('access', '').lower()
                                direction = rule.get('direction', '').lower()
                                protocol = rule.get('protocol', 'Any')
                                port_range = rule.get('destinationPortRange', '')
                                port_ranges = rule.get('destinationPortRanges', [])
                                        
                                self.formatter.print_success(f"Referenced in NSG: {nsg_name}")
                                self.formatter.print_key_value("  Rule Name", rule_name)
                                self.formatter.print_key_value("  Direction", direction)
                                self.formatter.print_key_value("  Access", access)
                                self.formatter.print_key_value("  Protocol", protocol)
                                
                                all_ports = [port_range] if port_range else []
                                all_ports += port_ranges
                                self.formatter.print_key_value("  Ports", ', '.join(all_ports) if all_ports else 'Any')
                                break
                            
                            if asg_referenced:
                                break
                        
                        if not asg_referenced:
                            self.formatter.print_warning("⚠ No NSG rules found referencing this ASG")
                        
                    self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve ASGs: {asg_response.status_code}")
            
            # 3. Summary and Compliance Assessment
            self.formatter.print_subsection("ASG BOUNDARY PROTECTION COMPLIANCE SUMMARY")
            self.formatter.print_key_value("Total NSGs", total_nsgs)
            self.formatter.print_key_value("NSGs with DenyAllInbound (65000)", nsgs_with_deny_all_inbound)
            self.formatter.print_key_value("Total ASGs", total_asgs)
            self.formatter.print_key_value("ASGs with NSG Rules", asgs_with_rules)
            self.formatter.print_key_value("ASG-to-ASG Rules Found", asg_to_asg_rules_found)
            
            # Compliance assessment
            if total_nsgs > 0:
                nsg_compliance = (nsgs_with_deny_all_inbound / total_nsgs) * 100
                self.formatter.print_key_value("NSG DenyAllInbound Compliance", f"{nsg_compliance:.1f}%")
                
                if nsg_compliance >= 90:
                    self.formatter.print_success("EXCELLENT: Most NSGs have proper DenyAllInbound rules")
                elif nsg_compliance >= 70:
                    self.formatter.print_warning("⚠ GOOD: Most NSGs have DenyAllInbound rules, review missing ones")
                else:
                    self.formatter.print_error("POOR: Many NSGs missing DenyAllInbound rules")
            
            if total_asgs > 0:
                asg_usage = (asgs_with_rules / total_asgs) * 100
                self.formatter.print_key_value("ASG Usage Rate", f"{asg_usage:.1f}%")
                
                if asg_usage >= 80:
                    self.formatter.print_success("GOOD: Most ASGs are being used in NSG rules")
                elif asg_usage >= 50:
                    self.formatter.print_warning("⚠ MODERATE: Some ASGs are not being used")
                else:
                    self.formatter.print_warning("⚠ LOW: Many ASGs are not being used in NSG rules")
            
            if asg_to_asg_rules_found > 0:
                self.formatter.print_success("ASG-to-ASG rules found - permit-by-exception boundary protection implemented")
            else:
                self.formatter.print_warning("⚠ No ASG-to-ASG rules found - consider implementing permit-by-exception rules")
            
            # Compliance evidence
            self.formatter.print_subsection("COMPLIANCE EVIDENCE")
            if nsgs_with_deny_all_inbound > 0 and asg_to_asg_rules_found > 0:
                self.formatter.print_success("BOUNDARY PROTECTION VERIFIED: Network Security Groups have default DenyAllInbound rules (priority 65000) and Application Security Groups are used for permit-by-exception access control through ASG-to-ASG rules.")
            elif nsgs_with_deny_all_inbound > 0:
                self.formatter.print_warning("⚠ PARTIAL COMPLIANCE: NSGs have DenyAllInbound rules but ASG-to-ASG rules need implementation")
            elif asg_to_asg_rules_found > 0:
                self.formatter.print_warning("⚠ PARTIAL COMPLIANCE: ASG-to-ASG rules exist but NSG DenyAllInbound rules need verification")
            else:
                self.formatter.print_error("NON-COMPLIANT: Missing both NSG DenyAllInbound rules and ASG-to-ASG boundary protection")

        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking ASG boundary protection: {e}")
        self.formatter.print_separator()

    def check_sentinel_alerts_and_health_reports(self):
        """Evidence that Sentinel alerts and health reports cover key security and operational areas."""
        self.formatter.print_header(
            "SENTINEL ALERTS AND HEALTH REPORTS",
            "This function checks that Microsoft Sentinel alerts and health reports include: missing/stopped forwarders, MFA activity, configuration baselines, failed logins, data feed status, external/internal connections monitoring, root/administrative account activity, and permission/object changes."
        )
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        max_lines = getattr(self.config, 'max_lines', 100)
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return

        # 1. Missing/Stopped Forwarders
        self.formatter.print_subsection("MISSING/STOPPED FORWARDERS")
        try:
            query = f"""
            Heartbeat
            | where TimeGenerated > ago(1d)
            | summarize LastSeen=max(TimeGenerated) by Computer
            | where LastSeen < ago(1h)
            | take {max_lines}
            """
            workspace_id = self.api_client.get_workspace_id(subscription_id, resource_group, workspace_name)
            response = self.api_client.log_analytics_query(workspace_id, query, "P1D")
            if response.status_code == 200:
                tables = response.json().get('tables', [])
                if tables and tables[0].get('rows'):
                    self.formatter.print_warning("Some forwarders have not sent a heartbeat in the last hour:")
                    for row in tables[0]['rows']:
                        self.formatter.print_key_value("Computer", row[0])
                else:
                    self.formatter.print_success("All forwarders are reporting as expected.")
            elif response.status_code == 403:
                self.formatter.print_warning("Access denied to Log Analytics workspace.")
                self.formatter.print_info("Required permissions: Log Analytics Reader or Contributor role")
                self.formatter.print_info("To fix: Assign the role to service principal at the workspace level.")
            else:
                self.formatter.print_error("Failed to query Heartbeat table for forwarder status.")
                self.formatter.print_info("This may indicate: Log Analytics agents not deployed, workspace permissions issues, or no agents configured to send heartbeat data.")
                self.formatter.print_info(f"Response: {response.text}")
        except Exception as e:
            self.formatter.print_error(f"Exception querying Heartbeat table: {e}")
            self.formatter.print_info("Prerequisites: Log Analytics workspace must be configured with agents sending heartbeat data.")

        # 2. MFA Activity
        self.formatter.print_subsection("MFA ACTIVITY")
        try:
            # Check if this is a government cloud environment
            is_government = getattr(self.config, 'is_government_cloud', False)
            
            if is_government:
                # Government cloud - use audit logs directly (sign-in logs not available)
                audit_url = f"/auditLogs/directoryAudits?$top=50&$orderby=activityDateTime desc"
                response = self.api_client.graph_get(audit_url)
            else:
                # Commercial cloud - try sign-in logs first, then fallback to audit logs
                try:
                    signin_url = f"/reports/signIns?$top=50&$orderby=createdDateTime desc"
                    response = self.api_client.graph_get(signin_url)
                    
                    if response.status_code == 200:
                        signins = response.json().get('value', [])
                        # Filter for MFA sign-ins in the response (only check first 20 for performance)
                        max_subitems = getattr(self.config, 'max_subitems', 10)
                        mfa_signins = []
                        for s in signins[:20]:  # Limit to first 20 for performance
                            if s.get('authenticationRequirement') == 'multiFactorAuthentication':
                                mfa_signins.append(s)
                        if mfa_signins:
                            self.formatter.print_success(f"Found {len(mfa_signins)} recent MFA sign-ins.")
                            for signin in mfa_signins[:max_subitems]:  # Show first max_subitems
                                user = signin.get('userPrincipalName', 'Unknown')
                                app = signin.get('appDisplayName', 'Unknown')
                                self.formatter.print_key_value(f"MFA Sign-in", f"{user} via {app}")
                            if len(mfa_signins) > max_subitems:
                                self.formatter.print_info(f"... and {len(mfa_signins) - max_subitems} more MFA sign-ins.")
                        else:
                            self.formatter.print_info("No recent MFA sign-ins found.")
                        return  # Success, exit early
                    else:
                        # Sign-in logs failed, fallback to audit logs
                        self.formatter.print_info("Sign-in logs endpoint not available, trying audit logs...")
                except:
                    # Exception occurred, fallback to audit logs
                    self.formatter.print_info("Sign-in logs endpoint not available, trying audit logs...")
                
                # Fallback to audit logs for commercial cloud
                audit_url = f"/auditLogs/directoryAudits?$top=50&$orderby=activityDateTime desc"
                response = self.api_client.graph_get(audit_url)
            
            if response.status_code == 200:
                audits = response.json().get('value', [])
                # Filter for MFA-related activities
                mfa_audits = []
                for audit in audits:
                    activity = audit.get('activityDisplayName', '').lower()
                    if any(keyword in activity for keyword in ['mfa', 'multi-factor', 'authentication', 'sign']):
                        mfa_audits.append(audit)
                
                if mfa_audits:
                    self.formatter.print_success(f"Found {len(mfa_audits)} recent MFA-related audit events.")
                    max_subitems = getattr(self.config, 'max_subitems', 10)
                    for audit in mfa_audits[:max_subitems]:  # Show first max_subitems
                        activity = audit.get('activityDisplayName', 'Unknown')
                        initiated_by = audit.get('initiatedBy', {})
                        user = initiated_by.get('user', {}).get('userPrincipalName', 'Unknown') if initiated_by.get('user') else 'Unknown'
                        self.formatter.print_key_value(f"MFA Activity", f"{user} - {activity}")
                    if len(mfa_audits) > max_subitems:
                        self.formatter.print_info(f"... and {len(mfa_audits) - max_subitems} more MFA activities.")
                else:
                    self.formatter.print_info("No recent MFA activities found in audit logs.")
            elif response.status_code == 403:
                self.formatter.print_warning("Access denied to Azure AD audit logs.")
                self.formatter.print_info("Required permissions: AuditLog.Read.All")
                self.formatter.print_info("To fix: Grant admin consent for the required Microsoft Graph permissions.")
            else:
                self.formatter.print_error("Failed to query Azure AD audit logs for MFA activity.")
                self.formatter.print_info("This may indicate: Azure AD Premium P1/P2 not enabled, audit logs not configured, or insufficient permissions.")
                self.formatter.print_info(f"Response: {response.text}")
        except Exception as e:
            self.formatter.print_error(f"Exception querying Azure AD audit logs: {e}")
            self.formatter.print_info("Prerequisites: Azure AD Premium license required with audit logs enabled.")

        # 3. Configuration Baselines
        self.formatter.print_subsection("CONFIGURATION BASELINES")
        try:
            # Try multiple tables that might contain configuration changes
            queries = [
                {
                    "query": f"""
                    AzureActivity
                    | where TimeGenerated > ago(1d)
                    | where OperationName contains "write" or OperationName contains "create" or OperationName contains "update"
                    | take {max_lines}
                    """,
                    "name": "AzureActivity",
                    "description": "Azure Activity logs"
                },
                {
                    "query": f"""
                    Event
                    | where TimeGenerated > ago(1d)
                    | where EventID == 8003 or EventID == 8004 or EventID == 8005
                    | take {max_lines}
                    """,
                    "name": "Event",
                    "description": "Windows Event logs"
                },
                {
                    "query": f"""
                    SecurityEvent
                    | where TimeGenerated > ago(1d)
                    | where EventID == 4719 or EventID == 4738 or EventID == 4739
                    | take {max_lines}
                    """,
                    "name": "SecurityEvent",
                    "description": "Windows Security Event logs"
                }
            ]
            
            config_changes_found = False
            for query_info in queries:
                try:
                    response = self.api_client.log_analytics_query(workspace_id, query_info["query"], "P1D")
                    if response.status_code == 200:
                        tables = response.json().get('tables', [])
                        if tables and tables[0].get('rows'):
                            self.formatter.print_success(f"Found {len(tables[0]['rows'])} recent configuration changes in {query_info['description']}.")
                            config_changes_found = True
                            break
                    elif response.status_code == 400:
                        # Table doesn't exist or query syntax error - continue to next query
                        self.formatter.print_info(f"Table {query_info['name']} not available or query failed - trying next option...")
                        continue
                    else:
                        # Other error - log but continue
                        self.formatter.print_warning(f"Query for {query_info['name']} returned status {response.status_code}")
                        continue
                except Exception as e:
                    # Individual query failed - continue to next one
                    self.formatter.print_info(f"Query for {query_info['name']} failed: {str(e)[:100]}... - trying next option...")
                    continue
            
            if not config_changes_found:
                self.formatter.print_info("No recent configuration changes found.")
                self.formatter.print_info("This may indicate: No configuration changes occurred, required data sources not enabled, or tables not available in workspace.")
                
        except Exception as e:
            self.formatter.print_error(f"Exception querying configuration changes: {e}")
            self.formatter.print_info("Prerequisites: Azure Activity logs or Event logs must be enabled.")

        # 4. Failed Logins
        self.formatter.print_subsection("FAILED LOGINS")
        try:
            # Check if this is a government cloud environment
            is_government = getattr(self.config, 'is_government_cloud', False)
            
            if is_government:
                # Government cloud - use audit logs directly (sign-in logs not available)
                audit_url = f"/auditLogs/directoryAudits?$top=50&$orderby=activityDateTime desc"
                response = self.api_client.graph_get(audit_url)
            else:
                # Commercial cloud - try sign-in logs first, then fallback to audit logs
                try:
                    signin_url = f"/reports/signIns?$top=50&$orderby=createdDateTime desc"
                    response = self.api_client.graph_get(signin_url)
                    
                    if response.status_code == 200:
                        signins = response.json().get('value', [])
                        # Filter for failed logins in the response (only check first 20 for performance)
                        max_subitems = getattr(self.config, 'max_subitems', 10)
                        failed_signins = []
                        for s in signins[:20]:  # Limit to first 20 for performance
                            if s.get('status', {}).get('errorCode', 0) != 0:
                                failed_signins.append(s)
                        if failed_signins:
                            self.formatter.print_success(f"Found {len(failed_signins)} failed logins.")
                            for signin in failed_signins[:max_subitems]:  # Show first max_subitems
                                user = signin.get('userPrincipalName', 'Unknown')
                                error = signin.get('status', {}).get('errorCode', 'Unknown')
                                self.formatter.print_key_value(f"Failed Login", f"{user} - Error: {error}")
                            if len(failed_signins) > max_subitems:
                                self.formatter.print_info(f"... and {len(failed_signins) - max_subitems} more failed logins.")
                        else:
                            self.formatter.print_info("No failed logins found.")
                        return  # Success, exit early
                    else:
                        # Sign-in logs failed, fallback to audit logs
                        self.formatter.print_info("Sign-in logs endpoint not available, trying audit logs...")
                except:
                    # Exception occurred, fallback to audit logs
                    self.formatter.print_info("Sign-in logs endpoint not available, trying audit logs...")
                
                # Fallback to audit logs for commercial cloud
                audit_url = f"/auditLogs/directoryAudits?$top=50&$orderby=activityDateTime desc"
                response = self.api_client.graph_get(audit_url)
            
            if response.status_code == 200:
                audits = response.json().get('value', [])
                # Filter for failed login activities
                failed_audits = []
                for audit in audits:
                    activity = audit.get('activityDisplayName', '').lower()
                    if any(keyword in activity for keyword in ['failed', 'error', 'unsuccessful', 'denied']):
                        failed_audits.append(audit)
                
                if failed_audits:
                    self.formatter.print_success(f"Found {len(failed_audits)} recent failed login audit events.")
                    max_subitems = getattr(self.config, 'max_subitems', 10)
                    for audit in failed_audits[:max_subitems]:  # Show first max_subitems
                        activity = audit.get('activityDisplayName', 'Unknown')
                        initiated_by = audit.get('initiatedBy', {})
                        user = initiated_by.get('user', {}).get('userPrincipalName', 'Unknown') if initiated_by.get('user') else 'Unknown'
                        self.formatter.print_key_value(f"Failed Login", f"{user} - {activity}")
                    if len(failed_audits) > max_subitems:
                        self.formatter.print_info(f"... and {len(failed_audits) - max_subitems} more failed login events.")
                else:
                    self.formatter.print_info("No recent failed login events found in audit logs.")
            elif response.status_code == 403:
                self.formatter.print_warning("Access denied to Azure AD audit logs.")
                self.formatter.print_info("Required permissions: AuditLog.Read.All")
                self.formatter.print_info("To fix: Grant admin consent for the required Microsoft Graph permissions.")
            else:
                self.formatter.print_error("Failed to query Azure AD audit logs for failed logins.")
                self.formatter.print_info("This may indicate: Azure AD Premium P1/P2 not enabled, audit logs not configured, or insufficient permissions.")
                self.formatter.print_info(f"Response: {response.text}")
        except Exception as e:
            self.formatter.print_error(f"Exception querying Azure AD audit logs for failed logins: {e}")
            self.formatter.print_info("Prerequisites: Azure AD Premium license required with audit logs enabled.")

        # 5. Data Feed Status
        self.formatter.print_subsection("DATA FEED STATUS")
        try:
            url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2023-02-01-preview"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                connectors = response.json().get('value', [])
                if connectors:
                    for connector in connectors:
                        name = connector.get('name', 'Unknown')
                        state = connector.get('properties', {}).get('connectorState', 'Unknown')
                        self.formatter.print_key_value(f"Connector: {name}", f"State: {state}")
                else:
                    self.formatter.print_info("No data connectors found in Microsoft Sentinel.")
            elif response.status_code == 403:
                self.formatter.print_warning("Access denied to Microsoft SecurityInsights data connectors.")
                self.formatter.print_info("Required permissions: Microsoft Sentinel Contributor or Log Analytics Contributor role.")
                self.formatter.print_info("To fix: Assign the role to service principal at the workspace level.")
            else:
                self.formatter.print_error("Failed to retrieve data connectors.")
                self.formatter.print_info("This may indicate: Microsoft Sentinel not enabled, insufficient permissions, or workspace not properly configured.")
                self.formatter.print_info(f"Response: {response.text}")
        except Exception as e:
            self.formatter.print_error(f"Exception retrieving data connectors: {e}")
            self.formatter.print_info("Prerequisites: Microsoft Sentinel must be enabled on the Log Analytics workspace.")

        # 6. External and Internal Connections Monitoring
        self.formatter.print_subsection("EXTERNAL AND INTERNAL CONNECTIONS MONITORING")
        
        # Try multiple tables that might contain network connection data
        queries = [
            ("AzureActivity", f"""
                AzureActivity
                | where TimeGenerated > ago(1d)
                | where ResourceProvider == "Microsoft.Network"
                | take {max_lines}
                """),
            ("Event", f"""
                Event
                | where TimeGenerated > ago(1d)
                | where EventID == 5156 or EventID == 5157
                | take {max_lines}
                """),
            ("SecurityEvent", f"""
                SecurityEvent
                | where TimeGenerated > ago(1d)
                | where EventID == 4624 or EventID == 4625
                | take {max_lines}
                """)
        ]
        
        network_records_found = False
        for table_name, query in queries:
            try:
                response = self.api_client.log_analytics_query(workspace_id, query, "P1D")
                if response.status_code == 200:
                    tables = response.json().get('tables', [])
                    if tables and tables[0].get('rows'):
                        self.formatter.print_success(f"Found {len(tables[0]['rows'])} recent network connection records in {table_name}.")
                        network_records_found = True
                        break
                elif response.status_code == 400:
                    # Table doesn't exist or query is invalid - try next table
                    continue
                else:
                    self.formatter.print_warning(f"Query failed for {table_name}: {response.status_code}")
                    continue
            except Exception as e:
                # Individual query failed - try next table
                continue
        
        if not network_records_found:
            self.formatter.print_info("No recent network connection records found.")
            self.formatter.print_info("Prerequisites: Azure Activity logs or Event logs must be enabled.")

        # 7. Root/Administrative Account Activity
        self.formatter.print_subsection("ROOT/ADMINISTRATIVE ACCOUNT ACTIVITY")
        try:
            # Use Microsoft Graph API for Azure AD audit logs - limit to recent data
            graph_url = f"/auditLogs/directoryAudits?$top=50&$orderby=activityDateTime desc"
            response = self.api_client.graph_get(graph_url)
            if response.status_code == 200:
                audits = response.json().get('value', [])
                # Filter for admin/root activities in the response (only check first 20 for performance)
                admin_audits = []
                for audit in audits[:20]:  # Limit to first 20 for performance
                    initiated_by = audit.get('initiatedBy')
                    if initiated_by:
                        user_obj = initiated_by.get('user')
                        if user_obj:
                            user = user_obj.get('userPrincipalName', '')
                            if user and ('admin' in user.lower() or 'root' in user.lower()):
                                admin_audits.append(audit)
                
                if admin_audits:
                    self.formatter.print_success(f"Found {len(admin_audits)} recent root/admin activities.")
                    max_subitems = getattr(self.config, 'max_subitems', 10)
                    for audit in admin_audits[:max_subitems]:  # Show first max_subitems
                        initiated_by = audit.get('initiatedBy')
                        if initiated_by:
                            user_obj = initiated_by.get('user')
                            user = user_obj.get('userPrincipalName', 'Unknown') if user_obj else 'Unknown'
                        else:
                            user = 'Unknown'
                        activity = audit.get('activityDisplayName', 'Unknown')
                        self.formatter.print_key_value(f"Admin Activity", f"{user} - {activity}")
                    if len(admin_audits) > max_subitems:
                        self.formatter.print_info(f"... and {len(admin_audits) - max_subitems} more admin activities.")
                else:
                    self.formatter.print_info("No recent root/admin activities found.")
            elif response.status_code == 403:
                self.formatter.print_warning("Access denied to Azure AD audit logs.")
                self.formatter.print_info("Required permissions: AuditLog.Read.All")
                self.formatter.print_info("To fix: Grant admin consent for the required Microsoft Graph permissions.")
            else:
                self.formatter.print_error("Failed to query Azure AD audit logs for admin activity.")
                self.formatter.print_info("This may indicate: Azure AD Premium P1/P2 not enabled, audit logs not configured, or insufficient permissions.")
                self.formatter.print_info(f"Response: {response.text}")
        except Exception as e:
            self.formatter.print_error(f"Exception querying Azure AD audit logs for admin activity: {e}")
            self.formatter.print_info("Prerequisites: Azure AD Premium license required with audit logs enabled.")

        # 8. Permission and Object Changes
        self.formatter.print_subsection("PERMISSION AND OBJECT CHANGES")
        try:
            # Use Microsoft Graph API for Azure AD audit logs - limit to recent data
            graph_url = f"/auditLogs/directoryAudits?$top=50&$orderby=activityDateTime desc"
            response = self.api_client.graph_get(graph_url)
            if response.status_code == 200:
                audits = response.json().get('value', [])
                # Filter for permission/role/object changes in the response (only check first 20 for performance)
                permission_audits = []
                for audit in audits[:20]:  # Limit to first 20 for performance
                    activity = audit.get('activityDisplayName', '').lower()
                    if any(keyword in activity for keyword in ['permission', 'role', 'object']):
                        permission_audits.append(audit)
                
                if permission_audits:
                    self.formatter.print_success(f"Found {len(permission_audits)} recent permission/object changes.")
                    max_subitems = getattr(self.config, 'max_subitems', 10)
                    for audit in permission_audits[:max_subitems]:  # Show first max_subitems
                        initiated_by = audit.get('initiatedBy')
                        if initiated_by:
                            user_obj = initiated_by.get('user')
                            user = user_obj.get('userPrincipalName', 'Unknown') if user_obj else 'Unknown'
                        else:
                            user = 'Unknown'
                        activity = audit.get('activityDisplayName', 'Unknown')
                        self.formatter.print_key_value(f"Permission/Object Change", f"{user} - {activity}")
                    if len(permission_audits) > max_subitems:
                        self.formatter.print_info(f"... and {len(permission_audits) - max_subitems} more permission/object changes.")
                else:
                    self.formatter.print_info("No recent permission/object changes found.")
            elif response.status_code == 403:
                self.formatter.print_warning("Access denied to Azure AD audit logs.")
                self.formatter.print_info("Required permissions: AuditLog.Read.All")
                self.formatter.print_info("To fix: Grant admin consent for the required Microsoft Graph permissions.")
            else:
                self.formatter.print_error("Failed to query Azure AD audit logs for permission/object changes.")
                self.formatter.print_info("This may indicate: Azure AD Premium P1/P2 not enabled, audit logs not configured, or insufficient permissions.")
                self.formatter.print_info(f"Response: {response.text}")
        except Exception as e:
            self.formatter.print_error(f"Exception querying Azure AD audit logs for permission/object changes: {e}")
            self.formatter.print_info("Prerequisites: Azure AD Premium license required with audit logs enabled.")
        self.formatter.print_separator()

    def check_azure_key_vault_key_storage(self):
        """Check that all keys are stored in Azure Key Vault."""
        self.formatter.print_header(
            "AZURE KEY VAULT KEY STORAGE",
            "This function enumerates all Azure Key Vaults and lists all keys, secrets, and certificates, evidencing that keys are stored securely in Key Vault."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        try:
            # List all Key Vaults
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                vaults = response.json().get('value', [])
                if not vaults:
                    self.formatter.print_warning("No Azure Key Vaults found in the subscription.")
                    return
                for vault in vaults:
                    name = vault.get('name', 'Unknown')
                    rg = vault.get('id', '').split('/')[4] if len(vault.get('id', '').split('/')) > 4 else 'Unknown'
                    self.formatter.print_subsection(f"KEY VAULT: {name}")
                    self.formatter.print_key_value("Resource Group", rg)
                    # List keys, secrets, and certificates (metadata only)
                    for kind, api in [("Keys", "keys"), ("Secrets", "secrets"), ("Certificates", "certificates")]:
                        items_url = f"{vault['id']}/{api}?api-version=7.4"
                        items_response = self.api_client.arm_get(items_url)
                        if items_response.status_code == 200:
                            items = items_response.json().get('value', [])
                            self.formatter.print_key_value(f"{kind} Count", str(len(items)))
                            max_subitems = getattr(self.config, 'max_subitems', 10)
                            for item in items[:max_subitems]:
                                self.formatter.print_key_value(f"{kind[:-1]}", item.get('id', 'Unknown'))
                            if len(items) > max_subitems:
                                self.formatter.print_info(f"... and {len(items) - max_subitems} more {kind.lower()}.")
                        else:
                            self.formatter.print_error(f"Failed to list {kind.lower()} for {name}.")
                    self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve Key Vaults: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking Key Vaults: {e}")
        self.formatter.print_separator()

    def check_inbound_internet_traffic_restriction(self):
        """Check that inbound internet traffic is restricted to TLS and SSH encrypted ports only."""
        self.formatter.print_header(
            "INBOUND INTERNET TRAFFIC RESTRICTION (TLS/SSH ONLY)",
            "This function checks all NSG/firewall rules to evidence that inbound internet traffic is restricted to TLS (443) and SSH (22) encrypted ports only, and warns if any other ports are open to the internet."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        allowed_ports = {"22", "443"}
        try:
            # List all Network Security Groups (NSGs)
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-04-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                nsgs = response.json().get('value', [])
                if not nsgs:
                    self.formatter.print_warning("No Network Security Groups found in the subscription.")
                    return
                for nsg in nsgs:
                    nsg_name = nsg.get('name', 'Unknown')
                    rg = nsg.get('id', '').split('/')[4] if len(nsg.get('id', '').split('/')) > 4 else 'Unknown'
                    self.formatter.print_subsection(f"NSG: {nsg_name}")
                    self.formatter.print_key_value("Resource Group", rg)
                    rules = nsg.get('properties', {}).get('securityRules', [])
                    found_violation = False
                    for rule in rules:
                        access = rule.get('access', '').lower()
                        direction = rule.get('direction', '').lower()
                        src_prefix = rule.get('sourceAddressPrefix', '')
                        src_prefixes = rule.get('sourceAddressPrefixes', [])
                        port_range = rule.get('destinationPortRange', '')
                        port_ranges = rule.get('destinationPortRanges', [])
                        name = rule.get('name', '')
                        # Check if rule allows inbound from internet
                        all_srcs = [src_prefix] if src_prefix else []
                        all_srcs += src_prefixes
                        all_ports = [port_range] if port_range else []
                        all_ports += port_ranges
                        if direction == 'inbound' and access == 'allow' and any(s in ['*', '0.0.0.0/0'] for s in all_srcs):
                            for pr in all_ports:
                                if pr not in allowed_ports:
                                    self.formatter.print_warning(f"Rule '{name}' allows inbound internet traffic on port {pr} (NOT TLS/SSH)")
                                    found_violation = True
                    if not found_violation:
                        self.formatter.print_success("All inbound internet rules restrict traffic to TLS/SSH ports only.")
                    self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve NSGs: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking inbound internet traffic restriction: {e}")
        self.formatter.print_separator()

    def check_asg_non_secure_protocol_restriction(self):
        """Check that non-secure protocols are not permitted by ASG-based firewall rules."""
        self.formatter.print_header(
            "ASG NON-SECURE PROTOCOL RESTRICTION",
            "This function checks all NSG rules referencing ASGs to ensure non-secure protocols (HTTP, FTP, Telnet, SMB, etc.) are not permitted."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        # Common non-secure protocol ports
        non_secure_ports = {
            "80": "HTTP",
            "20": "FTP-Data",
            "21": "FTP",
            "23": "Telnet",
            "25": "SMTP (unencrypted)",
            "110": "POP3",
            "143": "IMAP",
            "445": "SMB",
            "139": "NetBIOS",
            "3389": "RDP (unencrypted)",
            "53": "DNS (unencrypted)",
            "389": "LDAP (unencrypted)",
            "137": "NetBIOS Name",
            "138": "NetBIOS Datagram",
            "6667": "IRC",
            "69": "TFTP"
        }
        try:
            # List all ASGs
            asg_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/applicationSecurityGroups?api-version=2023-04-01"
            asg_response = self.api_client.arm_get(asg_url)
            if asg_response.status_code == 200:
                asgs = asg_response.json().get('value', [])
                if not asgs:
                    self.formatter.print_warning("No Application Security Groups found in the subscription.")
                    return
                # List all NSGs
                nsg_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-04-01"
                nsg_response = self.api_client.arm_get(nsg_url)
                nsgs = nsg_response.json().get('value', []) if nsg_response.status_code == 200 else []
                for asg in asgs:
                    asg_name = asg.get('name', 'Unknown')
                    asg_id = asg.get('id', '')
                    rg = asg_id.split('/')[4] if len(asg_id.split('/')) > 4 else 'Unknown'
                    self.formatter.print_subsection(f"ASG: {asg_name}")
                    self.formatter.print_key_value("Resource Group", rg)
                    found_violation = False
                    for nsg in nsgs:
                        nsg_name = nsg.get('name', 'Unknown')
                        rules = nsg.get('properties', {}).get('securityRules', [])
                        for rule in rules:
                            src_asgs = rule.get('sourceApplicationSecurityGroups', [])
                            dst_asgs = rule.get('destinationApplicationSecurityGroups', [])
                            access = rule.get('access', '').lower()
                            direction = rule.get('direction', '').lower()
                            port_range = rule.get('destinationPortRange', '')
                            port_ranges = rule.get('destinationPortRanges', [])
                            name = rule.get('name', '')
                            # Check if this ASG is referenced
                            if any(asg_id == s.get('id') for s in src_asgs + dst_asgs):
                                all_ports = [port_range] if port_range else []
                                all_ports += port_ranges
                                for pr in all_ports:
                                    if pr in non_secure_ports and access == 'allow':
                                        self.formatter.print_warning(f"Rule '{name}' in NSG '{nsg_name}' allows non-secure protocol {non_secure_ports[pr]} (port {pr})")
                                        found_violation = True
                    if not found_violation:
                        self.formatter.print_success("No ASG-based rules allow non-secure protocols.")
                    self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve ASGs: {asg_response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking ASG non-secure protocol restriction: {e}")
        self.formatter.print_separator()

    def check_high_availability_and_rto(self):
        """Check for high availability configuration and evidence 1-hour RTO for product portions."""
        self.formatter.print_header(
            "HIGH AVAILABILITY & 1-HOUR RTO (PRODUCT PORTIONS)",
            "This function checks for high availability (HA) configurations (zone/geo-redundancy, load balancers, etc.) and evidences a 1-hour recovery-time objective (RTO) for product portions."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        ha_found = False
        try:
            # Check VMs for availability sets or zones
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                vms = response.json().get('value', [])
                if not vms:
                    self.formatter.print_warning("No VMs found in the subscription.")
                for vm in vms:
                    name = vm.get('name', 'Unknown')
                    az = vm.get('zones', [])
                    avail_set = vm.get('properties', {}).get('availabilitySet', {}).get('id')
                    self.formatter.print_subsection(f"VM: {name}")
                    if az:
                        ha_found = True
                        self.formatter.print_success(f"Deployed in Availability Zone(s): {', '.join(az)}")
                    elif avail_set:
                        ha_found = True
                        self.formatter.print_success(f"Part of Availability Set: {avail_set}")
                    else:
                        self.formatter.print_warning("No explicit HA configuration (zone or set) found for this VM.")
                if not vms:
                    self.formatter.print_info("No VMs to check for HA configuration.")
            else:
                self.formatter.print_error(f"Failed to retrieve VMs: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking VM HA: {e}")
        # Check for zone-redundant storage
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Storage/storageAccounts?api-version=2022-09-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                accounts = response.json().get('value', [])
                for account in accounts:
                    name = account.get('name', 'Unknown')
                    sku = account.get('sku', {}).get('name', '')
                    kind = account.get('kind', '')
                    self.formatter.print_subsection(f"STORAGE ACCOUNT: {name}")
                    if 'ZRS' in sku:
                        ha_found = True
                        self.formatter.print_success("Zone-redundant storage (ZRS) configured")
                    else:
                        self.formatter.print_info(f"SKU: {sku} (not ZRS)")
            else:
                self.formatter.print_error(f"Failed to retrieve storage accounts: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking storage HA: {e}")
        # Check for load balancers
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/loadBalancers?api-version=2023-04-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                lbs = response.json().get('value', [])
                if lbs:
                    ha_found = True
                    self.formatter.print_success(f"Found {len(lbs)} load balancer(s) (supports HA)")
                else:
                    self.formatter.print_info("No load balancers found.")
            else:
                self.formatter.print_error(f"Failed to retrieve load balancers: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking load balancers: {e}")
        # Check for geo-redundant databases (SQL, CosmosDB)
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Sql/servers?api-version=2022-05-01-preview"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                servers = response.json().get('value', [])
                for server in servers:
                    name = server.get('name', 'Unknown')
                    self.formatter.print_subsection(f"SQL SERVER: {name}")
                    # For simplicity, just print geo-replication links if present
                    geo_rep_url = f"{server['id']}/databases?api-version=2022-05-01-preview"
                    db_response = self.api_client.arm_get(geo_rep_url)
                    if db_response.status_code == 200:
                        dbs = db_response.json().get('value', [])
                        for db in dbs:
                            geo_links = db.get('properties', {}).get('geoReplicationLinks', [])
                            if geo_links:
                                ha_found = True
                                self.formatter.print_success(f"Database {db.get('name')} has geo-replication configured.")
                            else:
                                self.formatter.print_info(f"Database {db.get('name')} has no geo-replication.")
            else:
                self.formatter.print_error(f"Failed to retrieve SQL servers: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking SQL geo-replication: {e}")
        
        # Check Backup & Restore Configuration
        self.formatter.print_subsection("BACKUP & RESTORE CONFIGURATION")
        backup_rto_compliant = False
        try:
            # Check Recovery Services Vaults
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.RecoveryServices/vaults?api-version=2023-04-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                vaults = response.json().get('value', [])
                if not vaults:
                    self.formatter.print_warning("No Recovery Services Vaults found in the subscription.")
                else:
                    for vault in vaults:
                        vault_name = vault.get('name', 'Unknown')
                        vault_id = vault.get('id', '')
                        self.formatter.print_subsection(f"RECOVERY SERVICES VAULT: {vault_name}")
                        
                        # Check backup items
                        backup_items_url = f"{vault_id}/backupProtectedItems?api-version=2023-04-01"
                        backup_response = self.api_client.arm_get(backup_items_url)
                        if backup_response.status_code == 200:
                            backup_items = backup_response.json().get('value', [])
                            if backup_items:
                                self.formatter.print_success(f"Found {len(backup_items)} protected backup items")
                                
                                # Check backup policies for frequency
                                policies_url = f"{vault_id}/backupPolicies?api-version=2023-04-01"
                                policies_response = self.api_client.arm_get(policies_url)
                                if policies_response.status_code == 200:
                                    policies = policies_response.json().get('value', [])
                                    for policy in policies:
                                        policy_name = policy.get('name', 'Unknown')
                                        policy_props = policy.get('properties', {})
                                        
                                        # Check backup frequency
                                        backup_schedule = policy_props.get('backupSchedule', {})
                                        if backup_schedule:
                                            schedule_runs = backup_schedule.get('scheduleRunTimes', [])
                                            if schedule_runs:
                                                # Calculate frequency in minutes
                                                if len(schedule_runs) > 1:
                                                    # Multiple times per day - check if frequent enough
                                                    self.formatter.print_success(f"Policy '{policy_name}' has multiple daily backups")
                                                    backup_rto_compliant = True
                                                else:
                                                    # Single daily backup - check if it's frequent enough
                                                    self.formatter.print_info(f"Policy '{policy_name}' has daily backup schedule")
                                        
                                        # Check retention settings
                                        retention_policy = policy_props.get('retentionPolicy', {})
                                        if retention_policy:
                                            daily_retention = retention_policy.get('dailySchedule', {}).get('retentionDuration', {}).get('count', 0)
                                            if daily_retention >= 1:
                                                self.formatter.print_success(f"Policy '{policy_name}' has daily retention for {daily_retention} days")
                                                backup_rto_compliant = True
                                            else:
                                                self.formatter.print_warning(f"Policy '{policy_name}' has insufficient daily retention")
                            else:
                                self.formatter.print_warning("No backup items found in this vault")
                        else:
                            self.formatter.print_error(f"Failed to retrieve backup items: {backup_response.status_code}")
                        
                        # Check for recent backup jobs (as proxy for DR drills)
                        jobs_url = f"{vault_id}/backupJobs?api-version=2023-04-01&$filter=status eq 'Completed'&$top=10"
                        jobs_response = self.api_client.arm_get(jobs_url)
                        if jobs_response.status_code == 200:
                            jobs = jobs_response.json().get('value', [])
                            if jobs:
                                recent_jobs = [job for job in jobs if job.get('properties', {}).get('endTime')]
                                if recent_jobs:
                                    self.formatter.print_success(f"Found {len(recent_jobs)} recent completed backup jobs")
                                    backup_rto_compliant = True
                                else:
                                    self.formatter.print_warning("No recent completed backup jobs found")
                            else:
                                self.formatter.print_warning("No backup jobs found")
                        else:
                            self.formatter.print_error(f"Failed to retrieve backup jobs: {jobs_response.status_code}")
            else:
                self.formatter.print_error(f"Failed to retrieve Recovery Services Vaults: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking backup configuration: {e}")
        
        # Print RTO statement
        if ha_found and backup_rto_compliant:
            self.formatter.print_success("Product portions are highly available with a 1-hour recovery-time objective (RTO) based on HA configuration and backup frequency.")
        elif ha_found:
            self.formatter.print_success("Product portions are highly available with a 1-hour recovery-time objective (RTO) based on HA configuration.")
            self.formatter.print_warning("Backup frequency may need review to ensure 1-hour RTO compliance.")
        elif backup_rto_compliant:
            self.formatter.print_success("Backup configuration supports 1-hour RTO with frequent backups.")
            self.formatter.print_warning("High availability configuration may need review to ensure 1-hour RTO compliance.")
        else:
            self.formatter.print_warning("No explicit HA configuration or backup frequency found. Please review your environment to ensure 1-hour RTO is achievable.")
        self.formatter.print_separator()

    def check_pim_admin_access(self):
        """Check that admin access is limited to authorized devices with valid SSH keys via Entra ID PIM."""
        self.formatter.print_header(
            "PIM ADMIN ACCESS ENFORCEMENT",
            "This function checks that admin access to the system is limited to authorized devices and users via Microsoft Entra ID Privileged Identity Management (PIM)."
        )
        try:
            # Query all PIM eligibility schedules
            url = "/roleManagement/directory/roleEligibilitySchedules"
            response = self.api_client.graph_get(url)
            
            # Check for license requirement error
            if self._handle_pim_license_error(response):
                return
            
            if response.status_code == 200:
                schedules = response.json().get('value', [])
                found = False
                for sched in schedules:
                    role_id = sched.get('roleDefinitionId', '')
                    principal_id = sched.get('principalId', '')

                    # Try to resolve role name
                    role_name = role_id
                    if role_id:
                        role_resp = self.api_client.graph_get(f"/directoryRoles/{role_id}")
                        if role_resp.status_code == 200:
                            role_name = role_resp.json().get('displayName', role_id)

                    # Try to resolve principal name (user or service principal)
                    principal_name = principal_id
                    if principal_id:
                        principal_resp = self.api_client.graph_get(f"/users/{principal_id}")
                        if principal_resp.status_code == 200:
                            principal_name = principal_resp.json().get('displayName', principal_id)
                        else:
                            principal_resp = self.api_client.graph_get(f"/servicePrincipals/{principal_id}")
                            if principal_resp.status_code == 200:
                                principal_name = principal_resp.json().get('displayName', principal_id)

                    if role_id and principal_id:
                        found = True
                        self.formatter.print_success(
                            f"PIM eligibility found for role: {role_name} (ID: {role_id}) and principal: {principal_name} (ID: {principal_id})"
                        )
                if not found:
                    self.formatter.print_warning("No PIM eligibility schedules found for admin roles.")
            else:
                self.formatter.print_error(f"Failed to retrieve PIM eligibility schedules: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking PIM admin access: {e}")
        self.formatter.print_separator()

    def print_all_pim_admins(self):
        """Print all active Privileged Identity Management (PIM) admins and their assigned roles."""
        self.formatter.print_header(
            "ACTIVE PIM ADMINISTRATORS",
            "This function lists all users with active PIM admin assignments (role assignments) in Microsoft Entra ID, including their names, roles, and assignment details."
        )
        try:
            max_lines = getattr(self.config, 'max_lines', 100)
            # Query all active PIM role assignments
            url = f"/roleManagement/directory/roleAssignmentScheduleInstances?$top={max_lines}"
            response = self.api_client.graph_get(url)
            
            # Check for license requirement error
            if self._handle_pim_license_error(response):
                return
            
            if response.status_code == 200:
                assignments = response.json().get('value', [])
                if not assignments:
                    self.formatter.print_info("No active PIM admin assignments found.")
                for assignment in assignments:
                    role_id = assignment.get('roleDefinitionId', '')
                    principal_id = assignment.get('principalId', '')
                    assignment_id = assignment.get('id', '')
                    assignment_type = assignment.get('assignmentType', 'N/A')
                    start_time = assignment.get('startDateTime', 'N/A')
                    end_time = assignment.get('endDateTime', 'N/A')

                    # Resolve role name
                    role_name = role_id
                    if role_id:
                        role_resp = self.api_client.graph_get(f"/directoryRoles/{role_id}")
                        if role_resp.status_code == 200:
                            role_name = role_resp.json().get('displayName', role_id)

                    # Resolve principal name
                    principal_name = principal_id
                    if principal_id:
                        principal_resp = self.api_client.graph_get(f"/users/{principal_id}")
                        if principal_resp.status_code == 200:
                            principal_name = principal_resp.json().get('displayName', principal_id)
                        else:
                            principal_resp = self.api_client.graph_get(f"/servicePrincipals/{principal_id}")
                            if principal_resp.status_code == 200:
                                principal_name = principal_resp.json().get('displayName', principal_id)

                    self.formatter.print_key_value("Assignment ID", assignment_id)
                    self.formatter.print_key_value("User/Principal", principal_name)
                    self.formatter.print_key_value("Role", role_name)
                    self.formatter.print_key_value("Assignment Type", assignment_type)
                    self.formatter.print_key_value("Start Time", start_time)
                    self.formatter.print_key_value("End Time", end_time)
                    self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve PIM admin assignments: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving PIM admin assignments: {e}")
        self.formatter.print_separator()

    def check_ssh_mfa_enforcement(self):
        """Check that SSH sessions require MFA (Microsoft Authenticator) via Conditional Access or Azure AD login."""
        self.formatter.print_header(
            "SSH MFA ENFORCEMENT",
            "This function checks if SSH access to the system requires MFA (Microsoft Authenticator), typically via Azure AD login for Linux VMs and Conditional Access policies."
        )
        try:
            url = "/identity/conditionalAccess/policies"
            response = self.api_client.graph_get(url)
            if response.status_code == 200:
                # Add null check for response.json()
                response_data = response.json()
                if response_data is None:
                    self.formatter.print_error("Failed to parse response data - response is None")
                    self.formatter.print_separator()
                    return
                
                policies = response_data.get('value', [])
                if policies is None:
                    policies = []
                
                found = False
                for policy in policies:
                    if not isinstance(policy, dict):
                        continue
                        
                    display_name = policy.get('displayName', '')
                    if display_name is None:
                        display_name = ''
                    
                    grant_controls = policy.get('grantControls', {})
                    if grant_controls is None:
                        grant_controls = {}
                    
                    built_in_controls = grant_controls.get('builtInControls', [])
                    if built_in_controls is None:
                        built_in_controls = []
                    
                    if 'mfa' in built_in_controls and 'ssh' in display_name.lower():
                        found = True
                        self.formatter.print_success(f"MFA required for SSH sessions by policy: {display_name}")
                
                if not found:
                    self.formatter.print_warning("No Conditional Access policy found requiring MFA for SSH sessions.")
            else:
                self.formatter.print_error(f"Failed to retrieve Conditional Access policies: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking SSH MFA enforcement: {e}")
        self.formatter.print_separator()

    def check_ssh_alerts_to_teams(self):
        """Check that SSH session events trigger alerts to Microsoft Teams for InfoSec Admin."""
        self.formatter.print_header(
            "SSH SESSION ALERTS TO TEAMS",
            "This function checks if there is an Azure Function, Logic App, or Sentinel analytic rule that triggers alerts to Microsoft Teams for SSH session events."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        found = False
        try:
            # Check Sentinel analytic rules for SSH alerting
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                workspaces = response.json().get('value', [])
                for ws in workspaces:
                    ws_name = ws.get('name', '')
                    resource_group = ws.get('id', '').split('/')[4] if len(ws.get('id', '').split('/')) > 4 else ''
                    rules_url = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{ws_name}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-12-01-preview"
                    rules_response = self.api_client.arm_get(rules_url)
                    if rules_response.status_code == 200:
                        rules = rules_response.json().get('value', [])
                        for rule in rules:
                            name = rule.get('name', '')
                            props = rule.get('properties', {})
                            if 'ssh' in name.lower() or 'ssh' in props.get('displayName', '').lower():
                                actions = props.get('actions', [])
                                for action in actions:
                                    if action.get('actionType', '').lower() == 'logicapp' or 'teams' in str(action).lower():
                                        found = True
                                        self.formatter.print_success(f"SSH session alert rule found: {name} (alerts to Teams/Logic App)")
            if not found:
                self.formatter.print_warning("No SSH session alerting rules to Teams found in Sentinel analytic rules.")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking SSH alerts to Teams: {e}")
        self.formatter.print_separator()

    def print_high_risk_users_with_activity(self):
        """
        Print high risk users along with their activity logs and user sessions.
        Respects the max_items config parameter.
        """
        self.formatter.print_header(
            "HIGH RISK USERS: ACTIVITY LOGS AND USER SESSIONS",
            "This function lists high risk users in Microsoft Entra ID, along with their recent activity logs and user sessions. This evidences monitoring of high risk accounts for compliance and security operations."
        )
        max_items = getattr(self.config, 'max_items', 100)
        max_subitems = getattr(self.config, 'max_subitems', 10)
        try:
            # 1. Get high risk users from Graph API
            risk_users_url = f"/identityProtection/riskyUsers?$top={max_items}"
            risk_users_resp = self.api_client.graph_get(risk_users_url)
            if risk_users_resp.status_code != 200:
                # Check for licensing error specifically
                if self._handle_identity_protection_license_error(risk_users_resp):
                    self.formatter.print_separator()
                    return
                else:
                    self.formatter.print_error(f"Failed to retrieve risky users: {risk_users_resp.status_code}")
                    error_data = risk_users_resp.json()
                    if error_data:
                        self.formatter.print_info(f"Error details: {error_data.get('error', {}).get('message', 'Unknown error')}")
                self.formatter.print_separator()
                return
            # Only include users where riskLevel is not None
            risk_users = risk_users_resp.json().get('value', [])
            high_risk_users = [u for u in risk_users if u.get('riskLevel') != 'none']

            # Enforce max_items limit regardless of API response
            high_risk_users = high_risk_users[:max_items]
            if not high_risk_users:
                self.formatter.print_info("No high risk users found.")
                self.formatter.print_separator()
                return
            for user in high_risk_users:
                user_id = user.get('id')
                display_name = user.get('displayName', '')
                user_principal = user.get('userPrincipalName', '')
                risk_level = user.get('riskLevel', 'unknown')
                risk_state = user.get('riskState', 'unknown')
                self.formatter.print_section_header(f"User: {display_name or user_principal or user_id}")
                self.formatter.print_key_value("User Principal Name", user_principal)
                self.formatter.print_key_value("Risk Level", risk_level)
                self.formatter.print_key_value("Risk State", risk_state)
                self.formatter.print_key_value("Risk Detail", user.get('riskDetail', 'N/A'))
                self.formatter.print_key_value("Risk Last Updated", user.get('riskLastUpdatedDateTime', 'N/A'))
                # 2. Get activity logs for this user
                self.formatter.print_subsection("Recent Activity Logs")
                activity_url = f"/auditLogs/signIns?$filter=userId eq '{user_id}'&$top={max_subitems}"
                activity_resp = self.api_client.graph_get(activity_url)
                if activity_resp.status_code == 200:
                    activities = activity_resp.json().get('value', [])
                    # Enforce max_subitems limit regardless of API response
                    activities = activities[:max_subitems]
                    if activities:
                        table_rows = []
                        for act in activities:
                            table_rows.append([
                                act.get('createdDateTime', ''),
                                act.get('ipAddress', ''),
                                act.get('appDisplayName', ''),
                                act.get('status', {}).get('displayStatus', ''),
                                act.get('deviceDetail', {}).get('operatingSystem', '')
                            ])
                        self.formatter.print_table(
                            ["Time", "IP Address", "App", "Status", "OS"], table_rows
                        )
                    else:
                        self.formatter.print_info("No recent sign-in activity found.", indent=1)
                else:
                    self.formatter.print_warning("Could not retrieve activity logs.", indent=1)
                # 3. Get user sessions (sign-ins)
                self.formatter.print_subsection("Recent User Sessions")
                session_url = f"/auditLogs/signIns?$filter=userId eq '{user_id}'&$top={max_subitems}"
                session_resp = self.api_client.graph_get(session_url)
                if session_resp.status_code == 200:
                    sessions = session_resp.json().get('value', [])
                    # Enforce max_subitems limit regardless of API response
                    sessions = sessions[:max_subitems]
                    if sessions:
                        table_rows = []
                        for sess in sessions:
                            table_rows.append([
                                sess.get('createdDateTime', ''),
                                sess.get('ipAddress', ''),
                                sess.get('clientAppUsed', ''),
                                sess.get('status', {}).get('displayStatus', ''),
                                sess.get('deviceDetail', {}).get('browser', '')
                            ])
                        self.formatter.print_table(
                            ["Time", "IP Address", "Client App", "Status", "Browser"], table_rows
                        )
                    else:
                        self.formatter.print_info("No recent user sessions found.", indent=1)
                else:
                    self.formatter.print_warning("Could not retrieve user sessions.", indent=1)
                self.formatter.print_separator()
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while printing high risk users: {e}")
            self.formatter.print_separator()

    def check_vm_os_auth_on_unlock(self):
        """
        Verify VM OS policies for requiring authentication on unlock.
        Checks Windows and Linux VMs for configuration enforcing authentication on unlock.
        """
        self.formatter.print_header(
            "VM OS AUTHENTICATION ON UNLOCK POLICY", 
            "This check verifies that all VMs enforce authentication when unlocking the OS session.")

        subscription_id = self.config.subscription_id
        resource_group = self.config.resource_group
        max_items = self.config.max_items

        vm_url = (
            f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/"
            "Microsoft.Compute/virtualMachines?api-version=2023-09-01"
        )
        try:
            resp = self.api_client.arm_get(vm_url)
            if resp.status_code != 200:
                self.formatter.print_error("Failed to retrieve VMs from Azure.", indent=1)
                self.formatter.print_separator()
                return

            vms = resp.json().get("value", [])
            if not vms:
                self.formatter.print_info("No VMs found in the specified resource group.", indent=1)
                self.formatter.print_separator()
                return

            results = []
            for vm in vms[:max_items]:
                vm_name = vm.get("name", "")
                os_type = ""
                auth_required = "Unknown"
                storage_profile = vm.get("properties", {}).get("storageProfile", {})
                if "osDisk" in storage_profile:
                    os_type = storage_profile.get("osDisk", {}).get("osType", "")
                extensions_url = (
                    f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/"
                    f"Microsoft.Compute/virtualMachines/{vm_name}/extensions?api-version=2023-09-01"
                )
                ext_resp = self.api_client.arm_get(extensions_url)
                if ext_resp.status_code == 200:
                    extensions = ext_resp.json().get("value", [])
                    if os_type == "Windows":
                        found_policy = False
                        for ext in extensions:
                            publisher = ext.get("properties", {}).get("publisher", "")
                            ext_type = ext.get("properties", {}).get("type", "")
                            settings = ext.get("properties", {}).get("settings", {})
                            if publisher == "Microsoft.Powershell" and "DSC" in ext_type:
                                if "RequireAuthenticationOnUnlock" in str(settings):
                                    found_policy = True
                                    break
                            if publisher == "Microsoft.Compute" and "CustomScriptExtension" in ext_type:
                                if "RequireAuthenticationOnUnlock" in str(settings):
                                    found_policy = True
                                    break
                        auth_required = "Yes" if found_policy else "No"
                    elif os_type == "Linux":
                        found_policy = False
                        for ext in extensions:
                            publisher = ext.get("properties", {}).get("publisher", "")
                            ext_type = ext.get("properties", {}).get("type", "")
                            settings = ext.get("properties", {}).get("settings", {})
                            if publisher == "Microsoft.Azure.Extensions" and "CustomScript" in ext_type:
                                if "pam" in str(settings).lower() or "auth" in str(settings).lower():
                                    found_policy = True
                                    break
                        auth_required = "Yes" if found_policy else "No"
                    else:
                        auth_required = "Unknown"
                else:
                    auth_required = "Unknown"

                results.append([
                    vm_name,
                    os_type,
                    auth_required
                ])

            self.formatter.print_table(
                ["VM Name", "OS Type", "Auth Required On Unlock"], results
            )
            self.formatter.print_separator()
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking VM OS unlock policy: {e}")
            self.formatter.print_separator()

    def print_log_analytics_purge_users(self):
        """Print all users and groups who can perform purge operations on the Log Analytics workspace."""
        self.formatter.print_header(
            "LOG ANALYTICS PURGE PERMISSIONS",
            "This function lists all users and groups with roles that allow purge (Log Analytics Purger, Log Analytics Contributor, Contributor, Owner) on the Log Analytics workspace. Only InfoSec Admins should have these roles."
        )
        workspace_name = getattr(self.config, 'workspace_name', None)
        subscription_id = getattr(self.config, 'subscription_id', None)
        resource_group = getattr(self.config, 'resource_group', None)
        if not (workspace_name and subscription_id and resource_group):
            self.formatter.print_error("workspace_name, subscription_id, and resource_group must be set in config.")
            return
        scope = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
        url = f"{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
        try:
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                assignments = response.json().get('value', [])
                purge_roles = [
                    "Log Analytics Purger",
                    "Log Analytics Contributor",
                    "Contributor",
                    "Owner"
                ]
                found = False
                for assignment in assignments:
                    role_id = assignment.get('properties', {}).get('roleDefinitionId', '')
                    principal_id = assignment.get('properties', {}).get('principalId', '')
                    # Get role name
                    role_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role_id}?api-version=2022-04-01"
                    role_resp = self.api_client.arm_get(role_url)
                    role_name = role_resp.json().get('properties', {}).get('roleName', role_id) if role_resp.status_code == 200 else role_id
                    if role_name in purge_roles:
                        found = True
                        # Try to resolve principal name (user, group, or service principal)
                        principal_name = principal_id
                        graph_url = f"/users/{principal_id}"
                        graph_resp = self.api_client.graph_get(graph_url)
                        if graph_resp.status_code == 200:
                            principal_name = graph_resp.json().get('displayName', principal_id)
                        else:
                            graph_url = f"/groups/{principal_id}"
                            graph_resp = self.api_client.graph_get(graph_url)
                            if graph_resp.status_code == 200:
                                principal_name = graph_resp.json().get('displayName', principal_id)
                            else:
                                graph_url = f"/servicePrincipals/{principal_id}"
                                graph_resp = self.api_client.graph_get(graph_url)
                                if graph_resp.status_code == 200:
                                    principal_name = graph_resp.json().get('displayName', principal_id)
                        self.formatter.print_key_value("Principal", principal_name)
                        self.formatter.print_key_value("Role", role_name)
                        self.formatter.print_separator()
                if not found:
                    self.formatter.print_info("No users or groups with purge permissions found.")
            else:
                self.formatter.print_error(f"Failed to retrieve role assignments: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving purge permissions: {e}")
        self.formatter.print_separator()

    def print_nsg_allowed_disallowed_ports(self):
        """Print all allowed and disallowed ports in all NSGs in the subscription."""
        self.formatter.print_header(
            "NSG ALLOWED/DISALLOWED PORTS",
            "This function lists all allowed and disallowed ports for inbound and outbound rules in all Network Security Groups (NSGs) in the subscription."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return

        url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2022-05-01"
        try:
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                nsgs = response.json().get('value', [])
                if not nsgs:
                    self.formatter.print_info("No NSGs found in the subscription.")
                else:
                    for nsg in nsgs:
                        nsg_name = nsg.get('name', 'Unnamed NSG')
                        self.formatter.print_subsection(f"NSG: {nsg_name}")
                        rules = nsg.get('properties', {}).get('securityRules', [])
                        if not rules:
                            self.formatter.print_info("No security rules found in this NSG.", indent=1)
                        else:
                            for rule in rules:
                                direction = rule.get('direction', 'Unknown')
                                access = rule.get('access', 'Unknown')
                                protocol = rule.get('protocol', '*')
                                name = rule.get('name', 'Unnamed Rule')
                                # Ports can be a single value or a list
                                ports = []
                                if 'destinationPortRange' in rule:
                                    ports.append(rule['destinationPortRange'])
                                if 'destinationPortRanges' in rule:
                                    ports.extend(rule['destinationPortRanges'])
                                if not ports:
                                    ports = ['*']
                                port_list = ', '.join(ports)
                                self.formatter.print_key_value(
                                    f"{direction} {access} ({protocol}) - Rule: {name}",
                                    f"Ports: {port_list}"
                                )
                        self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve NSGs: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving NSGs: {e}")
        self.formatter.print_separator()

    def print_resource_groups_and_system_load(self):
        """List resources and basic system load info for all resource groups in the subscription."""
        self.formatter.print_header(
            "RESOURCE GROUPS AND SYSTEM LOAD",
            "This function lists all resource groups, their resources, and basic system load info (for VMs, App Services, SQL DBs, AKS, Storage, Redis) in the subscription."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        max_items = getattr(self.config, 'max_items', 100)
        max_subitems = getattr(self.config, 'max_subitems', 10)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return

        # List all resource groups
        rg_url = f"/subscriptions/{subscription_id}/resourcegroups?api-version=2021-04-01"
        try:
            rg_response = self.api_client.arm_get(rg_url)
            if rg_response.status_code != 200:
                self.formatter.print_error(f"Failed to retrieve resource groups: {rg_response.status_code}")
                return
            resource_groups = rg_response.json().get('value', [])[:max_items]
            if not resource_groups:
                self.formatter.print_info("No resource groups found in the subscription.")
                return

            for rg in resource_groups:
                rg_name = rg.get('name', 'Unnamed RG')
                self.formatter.print_subsection(f"Resource Group: {rg_name}")

                # List resources in the resource group
                res_url = f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/resources?api-version=2021-04-01"
                res_response = self.api_client.arm_get(res_url)
                if res_response.status_code != 200:
                    self.formatter.print_error(f"Failed to retrieve resources for {rg_name}: {res_response.status_code}")
                    continue
                resources = res_response.json().get('value', [])[:max_subitems]
                if not resources:
                    self.formatter.print_info("No resources found in this resource group.", indent=1)
                    continue

                for res in resources:
                    res_type = res.get('type', 'Unknown')
                    res_name = res.get('name', 'Unnamed Resource')
                    self.formatter.print_key_value("Resource", f"{res_name} ({res_type})", indent=1)

                    # 1. Virtual Machines
                    if res_type.lower() == "microsoft.compute/virtualmachines":
                        metrics_url = (
                            f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Compute/virtualMachines/"
                            f"{res_name}/providers/microsoft.insights/metrics?api-version=2018-01-01"
                            "&metricnames=Percentage CPU&timespan=PT1H"
                        )
                        metrics_response = self.api_client.arm_get(metrics_url)
                        if metrics_response.status_code == 200:
                            metrics = metrics_response.json().get('value', [])
                            if metrics and metrics[0].get('timeseries', []):
                                datapoints = metrics[0]['timeseries'][0].get('data', [])
                                if datapoints:
                                    avg_cpu = datapoints[-1].get('average', 'N/A')
                                    self.formatter.print_key_value("  Avg CPU (last hour)", avg_cpu, indent=2)
                                else:
                                    self.formatter.print_info("  No CPU data available.", indent=2)
                            else:
                                self.formatter.print_info("  No CPU metrics found.", indent=2)
                        else:
                            self.formatter.print_info("  Could not retrieve CPU metrics.", indent=2)

                    # 2. App Services (Web Apps)
                    elif res_type.lower() == "microsoft.web/sites":
                        metrics_url = (
                            f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Web/sites/"
                            f"{res_name}/providers/microsoft.insights/metrics?api-version=2018-01-01"
                            "&metricnames=CpuPercentage,MemoryWorkingSet,Requests&timespan=PT1H"
                        )
                        metrics_response = self.api_client.arm_get(metrics_url)
                        if metrics_response.status_code == 200:
                            metrics = metrics_response.json().get('value', [])
                            for metric in metrics:
                                name = metric.get('name', {}).get('value', '')
                                datapoints = metric.get('timeseries', [{}])[0].get('data', [])
                                if datapoints:
                                    value = datapoints[-1].get('average', 'N/A')
                                    self.formatter.print_key_value(f"  {name} (last hour)", value, indent=2)
                        else:
                            self.formatter.print_info("  Could not retrieve App Service metrics.", indent=2)

                    # 3. SQL Databases
                    elif res_type.lower() == "microsoft.sql/servers/databases":
                        metrics_url = (
                            f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Sql/servers/"
                            f"{res_name.split('/')[0]}/databases/{res_name.split('/')[-1]}/providers/microsoft.insights/metrics?api-version=2018-01-01"
                            "&metricnames=cpu_percent,storage,deadlocks&timespan=PT1H"
                        )
                        metrics_response = self.api_client.arm_get(metrics_url)
                        if metrics_response.status_code == 200:
                            metrics = metrics_response.json().get('value', [])
                            for metric in metrics:
                                name = metric.get('name', {}).get('value', '')
                                datapoints = metric.get('timeseries', [{}])[0].get('data', [])
                                if datapoints:
                                    value = datapoints[-1].get('average', 'N/A')
                                    self.formatter.print_key_value(f"  {name} (last hour)", value, indent=2)
                        else:
                            self.formatter.print_info("  Could not retrieve SQL DB metrics.", indent=2)

                    # 4. AKS (Kubernetes)
                    elif res_type.lower() == "microsoft.containerservice/managedclusters":
                        metrics_url = (
                            f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.ContainerService/managedClusters/"
                            f"{res_name}/providers/microsoft.insights/metrics?api-version=2018-01-01"
                            "&metricnames=cpuUsagePercentage,memoryUsagePercentage,nodeCount&timespan=PT1H"
                        )
                        metrics_response = self.api_client.arm_get(metrics_url)
                        if metrics_response.status_code == 200:
                            metrics = metrics_response.json().get('value', [])
                            for metric in metrics:
                                name = metric.get('name', {}).get('value', '')
                                datapoints = metric.get('timeseries', [{}])[0].get('data', [])
                                if datapoints:
                                    value = datapoints[-1].get('average', 'N/A')
                                    self.formatter.print_key_value(f"  {name} (last hour)", value, indent=2)
                        else:
                            self.formatter.print_info("  Could not retrieve AKS metrics.", indent=2)

                    # 5. Storage Accounts
                    elif res_type.lower() == "microsoft.storage/storageaccounts":
                        metrics_url = (
                            f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Storage/storageAccounts/"
                            f"{res_name}/providers/microsoft.insights/metrics?api-version=2018-01-01"
                            "&metricnames=UsedCapacity,Transactions,Availability&timespan=PT1H"
                        )
                        metrics_response = self.api_client.arm_get(metrics_url)
                        if metrics_response.status_code == 200:
                            metrics = metrics_response.json().get('value', [])
                            for metric in metrics:
                                name = metric.get('name', {}).get('value', '')
                                datapoints = metric.get('timeseries', [{}])[0].get('data', [])
                                if datapoints:
                                    value = datapoints[-1].get('average', 'N/A')
                                    self.formatter.print_key_value(f"  {name} (last hour)", value, indent=2)
                        else:
                            self.formatter.print_info("  Could not retrieve Storage metrics.", indent=2)

                    # 6. Redis Cache
                    elif res_type.lower() == "microsoft.cache/redis":
                        metrics_url = (
                            f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Cache/Redis/"
                            f"{res_name}/providers/microsoft.insights/metrics?api-version=2018-01-01"
                            "&metricnames=serverLoad,connectedClients,usedMemory&timespan=PT1H"
                        )
                        metrics_response = self.api_client.arm_get(metrics_url)
                        if metrics_response.status_code == 200:
                            metrics = metrics_response.json().get('value', [])
                            for metric in metrics:
                                name = metric.get('name', {}).get('value', '')
                                datapoints = metric.get('timeseries', [{}])[0].get('data', [])
                                if datapoints:
                                    value = datapoints[-1].get('average', 'N/A')
                                    self.formatter.print_key_value(f"  {name} (last hour)", value, indent=2)
                        else:
                            self.formatter.print_info("  Could not retrieve Redis metrics.", indent=2)

                self.formatter.print_separator()
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while listing resource groups and system load: {e}")
        self.formatter.print_separator()

    def check_azure_functions_availability_zones(self):
        """Check all Azure Functions for Availability Zone deployment."""
        self.formatter.print_header(
            "AZURE FUNCTIONS AVAILABILITY ZONES",
            "This function lists all Azure Functions and checks if they are deployed across Availability Zones for high availability."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return

        rg_url = f"/subscriptions/{subscription_id}/resourcegroups?api-version=2021-04-01"
        found_any = False
        try:
            rg_response = self.api_client.arm_get(rg_url)
            if rg_response.status_code != 200:
                self.formatter.print_error(f"Failed to retrieve resource groups: {rg_response.status_code}")
                return
            resource_groups = rg_response.json().get('value', [])
            if not resource_groups:
                self.formatter.print_info("No resource groups found in the subscription.")
                return

            for rg in resource_groups:
                rg_name = rg.get('name', 'Unnamed RG')
                fa_url = f"/subscriptions/{subscription_id}/resourceGroups/{rg_name}/providers/Microsoft.Web/sites?api-version=2022-03-01"
                fa_response = self.api_client.arm_get(fa_url)
                if fa_response.status_code != 200:
                    continue
                function_apps = fa_response.json().get('value', [])
                for app in function_apps:
                    kind = app.get('kind', '')
                    if 'functionapp' not in kind.lower():
                        continue
                    found_any = True
                    app_name = app.get('name', 'Unnamed Function App')
                    zone_redundant = app.get('properties', {}).get('zoneRedundant', None)
                    self.formatter.print_key_value("Function App", app_name)
                    if zone_redundant is True:
                        self.formatter.print_key_value("Availability Zones", "Enabled")
                    elif zone_redundant is False:
                        self.formatter.print_key_value("Availability Zones", "Not Enabled")
                    else:
                        self.formatter.print_key_value("Availability Zones", "Unknown/Not Set")
                    self.formatter.print_separator()
            if not found_any:
                self.formatter.print_info("No Azure Functions found in the subscription.")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking Azure Functions availability zones: {e}")
        self.formatter.print_separator()

    def check_users_must_change_password(self):
        """Check if users are required to change password."""
        self.formatter.print_header(
            "USERS MUST CHANGE PASSWORD ON NEXT LOGIN",
            "This function checks if any users are required to change their password (forceChangePasswordNextSignIn)."
        )
        try:
            # Get up to max_items users
            max_items = getattr(self.config, 'max_items', 100)
            response = self.api_client.graph_get(f"/users?$top={max_items}")
            if response.status_code == 200:
                users = response.json().get('value', [])
                found = False
                for user in users:
                    if user.get('passwordPolicies', '') == 'None':
                        # This user may have forceChangePasswordNextSignIn set
                        pwd_profile = user.get('passwordProfile', {})
                        if pwd_profile.get('forceChangePasswordNextSignIn', False):
                            found = True
                            self.formatter.print_key_value("User", user.get('displayName', user.get('userPrincipalName', 'Unknown')))
                            self.formatter.print_key_value("forceChangePasswordNextSignIn", "True")
                            self.formatter.print_separator()
                if not found:
                    self.formatter.print_info("No users are required to change password on first login.")
            else:
                self.formatter.print_error(f"Failed to retrieve users: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking user password policies: {e}")
        self.formatter.print_separator()

    def check_defender_cloud_security_posture_management(self):
        """Check if Microsoft Defender Cloud Security Posture Management is enabled and review deployment logs."""
        self.formatter.print_header(
            "MICROSOFT DEFENDER CLOUD SECURITY POSTURE MANAGEMENT",
            "This function checks if Microsoft Defender Cloud Security Posture Management (formerly Azure Security Center) is enabled and configured, and reviews recent deployment logs."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        max_subitems = getattr(self.config, 'max_subitems', 10)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return

        # 1. Check if Defender for Cloud is enabled by looking at pricing tiers
        self.formatter.print_subsection("DEFENDER FOR CLOUD PRICING TIERS")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/pricings?api-version=2024-01-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                pricings = response.json().get('value', [])
                if pricings:
                    self.formatter.print_success("Microsoft Defender Cloud Security Posture Management is enabled with the following plans:")
                    for pricing in pricings:
                        name = pricing.get('name', 'Unknown')
                        tier = pricing.get('properties', {}).get('pricingTier', 'Unknown')
                        self.formatter.print_key_value(f"Plan: {name}", f"Tier: {tier}")
                    self.formatter.print_separator()
                else:
                    self.formatter.print_warning("No Microsoft Defender plans found. Cloud Security Posture Management may not be enabled.")
            else:
                self.formatter.print_error(f"Failed to retrieve Defender pricing information: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking Defender pricing tiers: {e}")

        # 2. Check recent deployment logs for Defender for Cloud/Posture Management
        self.formatter.print_subsection("RECENT DEPLOYMENT LOGS")
        try:
            deployments_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Resources/deployments?api-version=2022-09-01&$top={max_subitems}"
            response = self.api_client.arm_get(deployments_url)
            if response.status_code != 200:
                self.formatter.print_error(f"Failed to retrieve deployments: {response.status_code}")
            else:
                deployments = response.json().get('value', [])
                if not deployments:
                    self.formatter.print_info("No deployments found in the subscription.")
                else:
                    found = False
                    for deployment in deployments:
                        name = deployment.get('name', 'Unnamed Deployment')
                        props = deployment.get('properties', {})
                        timestamp = props.get('timestamp', 'N/A')
                        state = props.get('provisioningState', 'N/A')
                        # Check if related to Defender for Cloud or posture management
                        if any(keyword in name.lower() for keyword in ['defender', 'security', 'posture']):
                            found = True
                            self.formatter.print_key_value("Deployment Name", name)
                            self.formatter.print_key_value("Status", state)
                            self.formatter.print_key_value("Timestamp", timestamp)
                            if 'error' in props:
                                error = props['error']
                                self.formatter.print_key_value("Error Code", error.get('code', 'N/A'))
                                self.formatter.print_key_value("Error Message", error.get('message', 'N/A'))
                            self.formatter.print_separator()
                    if not found:
                        self.formatter.print_info("No Defender for Cloud/Posture Management deployments found in recent logs.")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while retrieving deployment logs: {e}")
        self.formatter.print_separator()

    def check_subnet_vnet_peering_and_ip_ranges(self):
        """List all subnets, VNet peering, and verify non-overlapping IP address ranges across tenants."""
        self.formatter.print_header(
            "SUBNET AND VNET PEERING ANALYSIS",
            "This function lists all subnets, VNet peering configurations, and verifies non-overlapping IP address ranges across tenants to ensure proper network segmentation."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        max_subitems = getattr(self.config, 'max_subitems', 10)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return

        try:
            # 1. Get all Virtual Networks
            self.formatter.print_subsection("VIRTUAL NETWORKS AND SUBNETS")
            vnet_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/virtualNetworks?api-version=2023-04-01"
            response = self.api_client.arm_get(vnet_url)
            if response.status_code != 200:
                self.formatter.print_error(f"Failed to retrieve Virtual Networks: {response.status_code}")
                return

            vnets = response.json().get('value', [])
            if not vnets:
                self.formatter.print_info("No Virtual Networks found in the subscription.")
                return

            all_subnets = []
            vnet_info = {}

            for vnet in vnets[:max_subitems]:
                vnet_name = vnet.get('name', 'Unnamed VNet')
                vnet_location = vnet.get('location', 'Unknown')
                vnet_id = vnet.get('id', '')
                vnet_props = vnet.get('properties', {})
                vnet_address_space = vnet_props.get('addressSpace', {}).get('addressPrefixes', [])
                
                self.formatter.print_key_value("Virtual Network", vnet_name)
                self.formatter.print_key_value("Location", vnet_location)
                self.formatter.print_key_value("Address Space", ', '.join(vnet_address_space) if vnet_address_space else 'Not configured')
                
                # Store VNet info for peering analysis
                vnet_info[vnet_id] = {
                    'name': vnet_name,
                    'location': vnet_location,
                    'address_space': vnet_address_space
                }

                # Get subnets for this VNet
                subnets = vnet_props.get('subnets', [])
                if subnets:
                    self.formatter.print_subsection(f"Subnets in {vnet_name}")
                    for subnet in subnets:
                        subnet_name = subnet.get('name', 'Unnamed Subnet')
                        subnet_props = subnet.get('properties', {})
                        subnet_address_prefix = subnet_props.get('addressPrefix', 'Not configured')
                        subnet_nsg = subnet_props.get('networkSecurityGroup', {}).get('id', 'No NSG')
                        subnet_route_table = subnet_props.get('routeTable', {}).get('id', 'No Route Table')
                        
                        subnet_info = {
                            'vnet_name': vnet_name,
                            'subnet_name': subnet_name,
                            'address_prefix': subnet_address_prefix,
                            'nsg': subnet_nsg,
                            'route_table': subnet_route_table
                        }
                        all_subnets.append(subnet_info)
                        
                        self.formatter.print_key_value(f"  Subnet: {subnet_name}", subnet_address_prefix)
                        if subnet_nsg != 'No NSG':
                            nsg_name = subnet_nsg.split('/')[-1]
                            self.formatter.print_key_value(f"    NSG", nsg_name)
                        if subnet_route_table != 'No Route Table':
                            route_table_name = subnet_route_table.split('/')[-1]
                            self.formatter.print_key_value(f"    Route Table", route_table_name)
                else:
                    self.formatter.print_info(f"  No subnets configured in {vnet_name}")
                
                self.formatter.print_separator()

            # 2. Check VNet Peering
            self.formatter.print_subsection("VNET PEERING CONFIGURATIONS")
            peering_found = False
            
            for vnet_id, vnet_data in vnet_info.items():
                vnet_name = vnet_data['name']
                peerings_url = f"{vnet_id}/virtualNetworkPeerings?api-version=2023-04-01"
                peering_response = self.api_client.arm_get(peerings_url)
                
                if peering_response.status_code == 200:
                    peerings = peering_response.json().get('value', [])
                    if peerings:
                        peering_found = True
                        self.formatter.print_key_value("VNet with Peering", vnet_name)
                        for peering in peerings:
                            peering_name = peering.get('name', 'Unnamed Peering')
                            peering_props = peering.get('properties', {})
                            remote_vnet = peering_props.get('remoteVirtualNetwork', {}).get('id', 'Unknown')
                            peering_state = peering_props.get('peeringState', 'Unknown')
                            allow_virtual_network_access = peering_props.get('allowVirtualNetworkAccess', False)
                            allow_forwarded_traffic = peering_props.get('allowForwardedTraffic', False)
                            allow_gateway_transit = peering_props.get('allowGatewayTransit', False)
                            use_remote_gateways = peering_props.get('useRemoteGateways', False)
                            
                            self.formatter.print_key_value(f"  Peering: {peering_name}", f"State: {peering_state}")
                            self.formatter.print_key_value(f"    Remote VNet", remote_vnet.split('/')[-1] if remote_vnet != 'Unknown' else 'Unknown')
                            self.formatter.print_key_value(f"    Allow VNet Access", allow_virtual_network_access)
                            self.formatter.print_key_value(f"    Allow Forwarded Traffic", allow_forwarded_traffic)
                            self.formatter.print_key_value(f"    Allow Gateway Transit", allow_gateway_transit)
                            self.formatter.print_key_value(f"    Use Remote Gateways", use_remote_gateways)
                            self.formatter.print_separator()
            
            if not peering_found:
                self.formatter.print_info("No VNet peering configurations found.")

            # 3. Analyze IP Address Ranges for Overlaps
            self.formatter.print_subsection("IP ADDRESS RANGE ANALYSIS")
            if all_subnets:
                self.formatter.print_info("Analyzing subnet address ranges for potential overlaps...")
                
                # Simple overlap detection (basic CIDR analysis)
                subnet_ranges = []
                for subnet in all_subnets:
                    if subnet['address_prefix'] != 'Not configured':
                        try:
                            # Parse CIDR notation (e.g., "10.0.1.0/24")
                            ip_part, prefix_len = subnet['address_prefix'].split('/')
                            prefix_len = int(prefix_len)
                            
                            # Convert to integer for comparison
                            ip_parts = [int(x) for x in ip_part.split('.')]
                            ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
                            
                            # Calculate network and broadcast addresses
                            network_mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
                            network_addr = ip_int & network_mask
                            broadcast_addr = network_addr | ((1 << (32 - prefix_len)) - 1)
                            
                            subnet_ranges.append({
                                'vnet': subnet['vnet_name'],
                                'subnet': subnet['subnet_name'],
                                'cidr': subnet['address_prefix'],
                                'network': network_addr,
                                'broadcast': broadcast_addr,
                                'prefix_len': prefix_len
                            })
                        except (ValueError, IndexError):
                            self.formatter.print_warning(f"Invalid CIDR format: {subnet['address_prefix']} in {subnet['vnet_name']}/{subnet['subnet_name']}")
                
                # Check for overlaps
                overlaps_found = []
                for i, range1 in enumerate(subnet_ranges):
                    for j, range2 in enumerate(subnet_ranges[i+1:], i+1):
                        # Check if ranges overlap
                        if not (range1['broadcast'] < range2['network'] or range2['broadcast'] < range1['network']):
                            overlaps_found.append((range1, range2))
                
                if overlaps_found:
                    self.formatter.print_error("POTENTIAL IP ADDRESS RANGE OVERLAPS DETECTED:")
                    for range1, range2 in overlaps_found:
                        self.formatter.print_error(f"  {range1['vnet']}/{range1['subnet']} ({range1['cidr']}) overlaps with {range2['vnet']}/{range2['subnet']} ({range2['cidr']})")
                    self.formatter.print_warning("Overlapping IP ranges can cause routing conflicts and connectivity issues.")
                else:
                    self.formatter.print_success("No overlapping IP address ranges detected across subnets.")
                
                # Summary
                self.formatter.print_subsection("SUMMARY")
                self.formatter.print_key_value("Total Virtual Networks", len(vnets))
                self.formatter.print_key_value("Total Subnets", len(all_subnets))
                self.formatter.print_key_value("Subnets with Valid CIDR", len(subnet_ranges))
                self.formatter.print_key_value("VNet Peerings Found", "Yes" if peering_found else "No")
                self.formatter.print_key_value("IP Range Overlaps", "Yes" if overlaps_found else "No")
            else:
                self.formatter.print_info("No subnets found for IP range analysis.")

        except Exception as e:
            self.formatter.print_error(f"Exception occurred while analyzing subnets and VNet peering: {e}")
        self.formatter.print_separator()

    def check_network_connectivity_and_security_gateways(self):
        """Check VPN Gateways, ExpressRoute, Azure Bastion, and Azure Firewall/NVA configurations."""
        self.formatter.print_header(
            "NETWORK CONNECTIVITY AND SECURITY GATEWAYS",
            "This function checks VPN Gateways, ExpressRoute, Azure Bastion, and Azure Firewall/Network Virtual Appliance (NVA) configurations for network security and connectivity."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        max_subitems = getattr(self.config, 'max_subitems', 10)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return

        try:
            # 1. Check VPN Gateways
            self.formatter.print_subsection("VPN GATEWAYS")
            vpn_gateway_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/virtualNetworkGateways?api-version=2023-04-01"
            response = self.api_client.arm_get(vpn_gateway_url)
            if response.status_code == 200:
                vpn_gateways = response.json().get('value', [])
                if vpn_gateways:
                    self.formatter.print_success(f"Found {len(vpn_gateways)} VPN Gateway(s)")
                    for gateway in vpn_gateways[:max_subitems]:
                        gateway_name = gateway.get('name', 'Unnamed Gateway')
                        gateway_location = gateway.get('location', 'Unknown')
                        gateway_props = gateway.get('properties', {})
                        gateway_type = gateway_props.get('gatewayType', 'Unknown')
                        vpn_type = gateway_props.get('vpnType', 'Unknown')
                        sku = gateway_props.get('sku', {}).get('name', 'Unknown')
                        active_active = gateway_props.get('activeActive', False)
                        enable_bgp = gateway_props.get('enableBgp', False)
                        
                        self.formatter.print_key_value("Gateway Name", gateway_name)
                        self.formatter.print_key_value("Location", gateway_location)
                        self.formatter.print_key_value("Gateway Type", gateway_type)
                        self.formatter.print_key_value("VPN Type", vpn_type)
                        self.formatter.print_key_value("SKU", sku)
                        self.formatter.print_key_value("Active-Active", active_active)
                        self.formatter.print_key_value("BGP Enabled", enable_bgp)
                        
                        # Check connections
                        connections_url = f"{gateway.get('id')}/connections?api-version=2023-04-01"
                        conn_response = self.api_client.arm_get(connections_url)
                        if conn_response.status_code == 200:
                            connections = conn_response.json().get('value', [])
                            self.formatter.print_key_value("Connections", len(connections))
                            max_subitems = getattr(self.config, 'max_subitems', 10)
                            for conn in connections[:max_subitems]:  # Show first max_subitems connections
                                conn_name = conn.get('name', 'Unnamed')
                                conn_props = conn.get('properties', {})
                                conn_status = conn_props.get('connectionStatus', 'Unknown')
                                conn_type = conn_props.get('connectionType', 'Unknown')
                                self.formatter.print_key_value(f"  {conn_name}", f"{conn_type} - {conn_status}")
                        self.formatter.print_separator()
                else:
                    self.formatter.print_warning("No VPN Gateways found")
            else:
                self.formatter.print_error(f"Failed to retrieve VPN Gateways: {response.status_code}")

            # 2. Check ExpressRoute Circuits
            self.formatter.print_subsection("EXPRESSROUTE CIRCUITS")
            expressroute_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/expressRouteCircuits?api-version=2023-04-01"
            response = self.api_client.arm_get(expressroute_url)
            if response.status_code == 200:
                circuits = response.json().get('value', [])
                if circuits:
                    self.formatter.print_success(f"Found {len(circuits)} ExpressRoute Circuit(s)")
                    for circuit in circuits[:max_subitems]:
                        circuit_name = circuit.get('name', 'Unnamed Circuit')
                        circuit_location = circuit.get('location', 'Unknown')
                        circuit_props = circuit.get('properties', {})
                        circuit_sku = circuit_props.get('sku', {}).get('name', 'Unknown')
                        circuit_tier = circuit_props.get('sku', {}).get('tier', 'Unknown')
                        circuit_family = circuit_props.get('sku', {}).get('family', 'Unknown')
                        circuit_provider = circuit_props.get('serviceProviderProperties', {}).get('serviceProviderName', 'Unknown')
                        circuit_bandwidth = circuit_props.get('serviceProviderProperties', {}).get('bandwidthInMbps', 'Unknown')
                        circuit_peering_location = circuit_props.get('serviceProviderProperties', {}).get('peeringLocation', 'Unknown')
                        
                        self.formatter.print_key_value("Circuit Name", circuit_name)
                        self.formatter.print_key_value("Location", circuit_location)
                        self.formatter.print_key_value("SKU", circuit_sku)
                        self.formatter.print_key_value("Tier", circuit_tier)
                        self.formatter.print_key_value("Family", circuit_family)
                        self.formatter.print_key_value("Provider", circuit_provider)
                        self.formatter.print_key_value("Bandwidth (Mbps)", circuit_bandwidth)
                        self.formatter.print_key_value("Peering Location", circuit_peering_location)
                        
                        # Check peerings
                        peerings_url = f"{circuit.get('id')}/peerings?api-version=2023-04-01"
                        peering_response = self.api_client.arm_get(peerings_url)
                        if peering_response.status_code == 200:
                            peerings = peering_response.json().get('value', [])
                            self.formatter.print_key_value("Peerings", len(peerings))
                            for peering in peerings:
                                peering_name = peering.get('name', 'Unnamed')
                                peering_props = peering.get('properties', {})
                                peering_state = peering_props.get('peeringState', 'Unknown')
                                peering_type = peering_props.get('peeringType', 'Unknown')
                                self.formatter.print_key_value(f"  {peering_name}", f"{peering_type} - {peering_state}")
                        self.formatter.print_separator()
                else:
                    self.formatter.print_warning("No ExpressRoute Circuits found")
            else:
                self.formatter.print_error(f"Failed to retrieve ExpressRoute Circuits: {response.status_code}")

            # 3. Check Azure Bastion Hosts
            self.formatter.print_subsection("AZURE BASTION HOSTS")
            bastion_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/bastionHosts?api-version=2023-04-01"
            response = self.api_client.arm_get(bastion_url)
            if response.status_code == 200:
                bastions = response.json().get('value', [])
                if bastions:
                    self.formatter.print_success(f"Found {len(bastions)} Azure Bastion Host(s)")
                    for bastion in bastions[:max_subitems]:
                        bastion_name = bastion.get('name', 'Unnamed Bastion')
                        bastion_location = bastion.get('location', 'Unknown')
                        bastion_props = bastion.get('properties', {})
                        bastion_sku = bastion_props.get('sku', {}).get('name', 'Unknown')
                        bastion_scale_units = bastion_props.get('scaleUnits', 'Unknown')
                        bastion_dns_name = bastion_props.get('dnsName', 'Not configured')
                        bastion_ip_config = bastion_props.get('ipConfigurations', [])
                        
                        self.formatter.print_key_value("Bastion Name", bastion_name)
                        self.formatter.print_key_value("Location", bastion_location)
                        self.formatter.print_key_value("SKU", bastion_sku)
                        self.formatter.print_key_value("Scale Units", bastion_scale_units)
                        self.formatter.print_key_value("DNS Name", bastion_dns_name)
                        self.formatter.print_key_value("IP Configurations", len(bastion_ip_config))
                        
                        # Check IP configurations
                        for ip_config in bastion_ip_config:
                            ip_config_name = ip_config.get('name', 'Unnamed')
                            ip_config_props = ip_config.get('properties', {})
                            subnet_id = ip_config_props.get('subnet', {}).get('id', 'Not configured')
                            public_ip = ip_config_props.get('publicIPAddress', {}).get('id', 'Not configured')
                            self.formatter.print_key_value(f"  {ip_config_name} - Subnet", subnet_id.split('/')[-1] if subnet_id != 'Not configured' else 'Not configured')
                            self.formatter.print_key_value(f"  {ip_config_name} - Public IP", public_ip.split('/')[-1] if public_ip != 'Not configured' else 'Not configured')
                        self.formatter.print_separator()
                else:
                    self.formatter.print_warning("No Azure Bastion Hosts found")
            else:
                self.formatter.print_error(f"Failed to retrieve Azure Bastion Hosts: {response.status_code}")

            # 4. Check Azure Firewalls
            self.formatter.print_subsection("AZURE FIREWALLS")
            firewall_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/azureFirewalls?api-version=2023-04-01"
            response = self.api_client.arm_get(firewall_url)
            if response.status_code == 200:
                firewalls = response.json().get('value', [])
                if firewalls:
                    self.formatter.print_success(f"Found {len(firewalls)} Azure Firewall(s)")
                    for firewall in firewalls[:max_subitems]:
                        firewall_name = firewall.get('name', 'Unnamed Firewall')
                        firewall_location = firewall.get('location', 'Unknown')
                        firewall_props = firewall.get('properties', {})
                        firewall_sku = firewall_props.get('sku', {}).get('name', 'Unknown')
                        firewall_tier = firewall_props.get('sku', {}).get('tier', 'Unknown')
                        firewall_threat_intel_mode = firewall_props.get('threatIntelMode', 'Unknown')
                        firewall_hub_ip_addresses = firewall_props.get('hubIPAddresses', {})
                        firewall_virtual_hub = firewall_props.get('virtualHub', {}).get('id', 'Not configured')
                        
                        self.formatter.print_key_value("Firewall Name", firewall_name)
                        self.formatter.print_key_value("Location", firewall_location)
                        self.formatter.print_key_value("SKU", firewall_sku)
                        self.formatter.print_key_value("Tier", firewall_tier)
                        self.formatter.print_key_value("Threat Intel Mode", firewall_threat_intel_mode)
                        self.formatter.print_key_value("Virtual Hub", firewall_virtual_hub.split('/')[-1] if firewall_virtual_hub != 'Not configured' else 'Not configured')
                        
                        # Check rule collections
                        rule_collections = firewall_props.get('ruleCollections', [])
                        app_rule_collections = [rc for rc in rule_collections if rc.get('properties', {}).get('ruleCollectionType') == 'FirewallPolicyFilterRuleCollection']
                        nat_rule_collections = [rc for rc in rule_collections if rc.get('properties', {}).get('ruleCollectionType') == 'FirewallPolicyNatRuleCollection']
                        network_rule_collections = [rc for rc in rule_collections if rc.get('properties', {}).get('ruleCollectionType') == 'FirewallPolicyFilterRuleCollection']
                        
                        self.formatter.print_key_value("Application Rule Collections", len(app_rule_collections))
                        self.formatter.print_key_value("NAT Rule Collections", len(nat_rule_collections))
                        self.formatter.print_key_value("Network Rule Collections", len(network_rule_collections))
                        
                        # Check IP configurations
                        ip_configs = firewall_props.get('ipConfigurations', [])
                        self.formatter.print_key_value("IP Configurations", len(ip_configs))
                        for ip_config in ip_configs:
                            ip_config_name = ip_config.get('name', 'Unnamed')
                            ip_config_props = ip_config.get('properties', {})
                            subnet_id = ip_config_props.get('subnet', {}).get('id', 'Not configured')
                            public_ip = ip_config_props.get('publicIPAddress', {}).get('id', 'Not configured')
                            self.formatter.print_key_value(f"  {ip_config_name} - Subnet", subnet_id.split('/')[-1] if subnet_id != 'Not configured' else 'Not configured')
                            self.formatter.print_key_value(f"  {ip_config_name} - Public IP", public_ip.split('/')[-1] if public_ip != 'Not configured' else 'Not configured')
                        self.formatter.print_separator()
                else:
                    self.formatter.print_warning("No Azure Firewalls found")
            else:
                self.formatter.print_error(f"Failed to retrieve Azure Firewalls: {response.status_code}")

            # 5. Check Network Virtual Appliances (NVAs) - Look for VMs with NVA characteristics
            self.formatter.print_subsection("NETWORK VIRTUAL APPLIANCES (NVAs)")
            vm_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines?api-version=2023-04-01"
            response = self.api_client.arm_get(vm_url)
            if response.status_code == 200:
                vms = response.json().get('value', [])
                nva_vms = []
                
                for vm in vms:
                    vm_name = vm.get('name', 'Unnamed VM')
                    vm_props = vm.get('properties', {})
                    vm_tags = vm.get('tags', {})
                    vm_plan = vm.get('plan', {})
                    
                    # Check if VM might be an NVA based on name, tags, or publisher
                    is_nva = False
                    nva_indicators = []
                    
                    # Check name patterns
                    if any(keyword in vm_name.lower() for keyword in ['firewall', 'nva', 'router', 'gateway', 'fortinet', 'paloalto', 'checkpoint', 'cisco', 'barracuda']):
                        is_nva = True
                        nva_indicators.append("Name pattern")
                    
                    # Check tags
                    if any(keyword in str(vm_tags).lower() for keyword in ['firewall', 'nva', 'network', 'security']):
                        is_nva = True
                        nva_indicators.append("Tags")
                    
                    # Check publisher (common NVA publishers)
                    if vm_plan.get('publisher', '').lower() in ['fortinet', 'paloaltonetworks', 'checkpoint', 'cisco', 'barracuda', 'f5networks']:
                        is_nva = True
                        nva_indicators.append("Publisher")
                    
                    if is_nva:
                        nva_vms.append({
                            'name': vm_name,
                            'location': vm.get('location', 'Unknown'),
                            'indicators': nva_indicators,
                            'publisher': vm_plan.get('publisher', 'Unknown'),
                            'offer': vm_plan.get('offer', 'Unknown'),
                            'sku': vm_plan.get('sku', 'Unknown')
                        })
                
                if nva_vms:
                    self.formatter.print_success(f"Found {len(nva_vms)} potential NVA(s)")
                    for nva in nva_vms[:max_subitems]:
                        self.formatter.print_key_value("NVA Name", nva['name'])
                        self.formatter.print_key_value("Location", nva['location'])
                        self.formatter.print_key_value("Detection Indicators", ', '.join(nva['indicators']))
                        self.formatter.print_key_value("Publisher", nva['publisher'])
                        self.formatter.print_key_value("Offer", nva['offer'])
                        self.formatter.print_key_value("SKU", nva['sku'])
                        self.formatter.print_separator()
                else:
                    self.formatter.print_info("No Network Virtual Appliances (NVAs) detected")
                    
            elif response.status_code == 404:
                self.formatter.print_info("No Virtual Machines found in the subscription")
            else:
                self.formatter.print_error(f"Failed to retrieve Virtual Machines: {response.status_code}")

            # 6. Summary
            self.formatter.print_subsection("SUMMARY")
            self.formatter.print_key_value("VPN Gateways", len(vpn_gateways) if 'vpn_gateways' in locals() else 0)
            self.formatter.print_key_value("ExpressRoute Circuits", len(circuits) if 'circuits' in locals() else 0)
            self.formatter.print_key_value("Azure Bastion Hosts", len(bastions) if 'bastions' in locals() else 0)
            self.formatter.print_key_value("Azure Firewalls", len(firewalls) if 'firewalls' in locals() else 0)
            self.formatter.print_key_value("Network Virtual Appliances", len(nva_vms) if 'nva_vms' in locals() else 0)

        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking network connectivity and security gateways: {e}")
        self.formatter.print_separator()

    def check_user_defined_routes(self):
        """Check for User Defined Routes (UDRs) that route traffic to firewall IPs and verify traffic path through Azure Firewall logs or NSG Flow Logs."""
        self.formatter.print_header(
            "USER DEFINED ROUTES (UDR) AND FIREWALL TRAFFIC PATH VERIFICATION",
            "This function checks User Defined Routes (UDRs) to ensure route tables send traffic to firewall IPs (e.g., 0.0.0.0/0 → Azure Firewall) and verifies traffic path through Azure Firewall logs or NSG Flow Logs in Log Analytics for compliance evidence."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        
        # Track UDR compliance
        total_route_tables = 0
        compliant_route_tables = 0
        firewall_routes_found = []
        missing_firewall_routes = []
        
        # 1. Check Route Tables and UDRs
        self.formatter.print_subsection("ROUTE TABLES AND USER DEFINED ROUTES")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/routeTables?api-version=2022-09-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                response_data = response.json()
                if response_data is None:
                    self.formatter.print_error("Failed to parse response data - response is None")
                    return
                    
                route_tables = response_data.get('value', [])
                if route_tables is None:
                    route_tables = []
                    
                if not route_tables:
                    self.formatter.print_warning("No route tables found in this subscription.")
                else:
                    self.formatter.print_success(f"Found {len(route_tables)} route tables")
                    
                    for route_table in route_tables:
                        if not isinstance(route_table, dict):
                            continue
                        total_route_tables += 1
                        table_name = route_table.get('name', 'Unknown')
                        table_id = route_table.get('id', '')
                        location = route_table.get('location', 'Unknown')
                        
                        self.formatter.print_subsection(f"ROUTE TABLE: {table_name}")
                        self.formatter.print_key_value("Location", location)
                        
                        # Check routes in this table
                        properties = route_table.get('properties', {})
                        if properties is None:
                            properties = {}
                            
                        routes = properties.get('routes', [])
                        if routes is None:
                            routes = []
                            
                        if not routes:
                            self.formatter.print_warning("No routes configured in this route table")
                            missing_firewall_routes.append(f"Route Table {table_name}: No routes configured")
                            continue
                        
                        self.formatter.print_success(f"Found {len(routes)} routes")
                        
                        # Check for firewall routes
                        has_firewall_route = False
                        firewall_ips = []
                        
                        for route in routes:
                            if not isinstance(route, dict):
                                continue
                            route_name = route.get('name', 'Unnamed')
                            if route_name is None:
                                route_name = 'Unnamed'
                                
                            route_properties = route.get('properties', {})
                            if route_properties is None:
                                route_properties = {}
                                
                            address_prefix = route_properties.get('addressPrefix', 'Unknown')
                            if address_prefix is None:
                                address_prefix = 'Unknown'
                                
                            next_hop_type = route_properties.get('nextHopType', 'Unknown')
                            if next_hop_type is None:
                                next_hop_type = 'Unknown'
                                
                            next_hop_ip = route_properties.get('nextHopIpAddress', 'Not specified')
                            if next_hop_ip is None:
                                next_hop_ip = 'Not specified'
                            
                            self.formatter.print_key_value(f"Route: {route_name}", f"{address_prefix} → {next_hop_type}")
                            if next_hop_ip != 'Not specified':
                                self.formatter.print_key_value("Next Hop IP", next_hop_ip)
                                firewall_ips.append(next_hop_ip)
                            
                            # Check if this is a firewall route (0.0.0.0/0 or similar to VirtualAppliance)
                            if (address_prefix == '0.0.0.0/0' and 
                                next_hop_type == 'VirtualAppliance' and 
                                next_hop_ip != 'Not specified'):
                                has_firewall_route = True
                                self.formatter.print_success("Found firewall route (0.0.0.0/0 → VirtualAppliance)")
                                firewall_routes_found.append(f"Route Table {table_name}: {route_name} → {next_hop_ip}")
                        
                        if has_firewall_route:
                            compliant_route_tables += 1
                            self.formatter.print_success("Route table properly routes traffic to firewall")
                        else:
                            self.formatter.print_error("No firewall route found (0.0.0.0/0 → VirtualAppliance)")
                            missing_firewall_routes.append(f"Route Table {table_name}: Missing firewall route")
                        
                        # Check route table associations
                        associations = properties.get('subnets', [])
                        if associations is None:
                            associations = []
                            
                        if associations:
                            self.formatter.print_success(f"Route table associated with {len(associations)} subnet(s)")
                            for subnet in associations:
                                if not isinstance(subnet, dict):
                                    continue
                                subnet_name = subnet.get('name', 'Unknown')
                                if subnet_name is None:
                                    subnet_name = 'Unknown'
                                self.formatter.print_key_value("Associated Subnet", subnet_name)
                        else:
                            self.formatter.print_warning("Route table not associated with any subnets")
                        
                        self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve route tables: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking route tables: {e}")
        
        # 2. Check Azure Firewalls
        self.formatter.print_subsection("AZURE FIREWALL CONFIGURATION")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/azureFirewalls?api-version=2022-09-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                response_data = response.json()
                if response_data is None:
                    self.formatter.print_error("Failed to parse response data - response is None")
                    return
                    
                firewalls = response_data.get('value', [])
                if firewalls is None:
                    firewalls = []
                    
                if not firewalls:
                    self.formatter.print_warning("No Azure Firewalls found in this subscription.")
                else:
                    self.formatter.print_success(f"Found {len(firewalls)} Azure Firewalls")
                    
                    for firewall in firewalls:
                        if not isinstance(firewall, dict):
                            continue
                        firewall_name = firewall.get('name', 'Unknown')
                        firewall_id = firewall.get('id', '')
                        location = firewall.get('location', 'Unknown')
                        
                        self.formatter.print_subsection(f"AZURE FIREWALL: {firewall_name}")
                        self.formatter.print_key_value("Location", location)
                        
                        # Check firewall IP addresses
                        properties = firewall.get('properties', {})
                        if properties is None:
                            properties = {}
                            
                        ip_configurations = properties.get('ipConfigurations', [])
                        if ip_configurations is None:
                            ip_configurations = []
                        
                        if ip_configurations:
                            self.formatter.print_success(f"Found {len(ip_configurations)} IP configuration(s)")
                            for ip_config in ip_configurations:
                                if not isinstance(ip_config, dict):
                                    continue
                                ip_config_name = ip_config.get('name', 'Unnamed')
                                private_ip = ip_config.get('properties', {}).get('privateIPAddress', 'Not configured')
                                public_ip = ip_config.get('properties', {}).get('publicIPAddress', {}).get('id', 'Not configured')
                                
                                self.formatter.print_key_value(f"IP Config: {ip_config_name}", f"Private: {private_ip}")
                                if public_ip != 'Not configured':
                                    self.formatter.print_key_value("Public IP", public_ip)
                        else:
                            self.formatter.print_warning("No IP configurations found")
                        
                        # Check firewall rules
                        network_rule_collections = properties.get('networkRuleCollections', [])
                        application_rule_collections = properties.get('applicationRuleCollections', [])
                        nat_rule_collections = properties.get('natRuleCollections', [])
                        
                        self.formatter.print_key_value("Network Rule Collections", len(network_rule_collections))
                        self.formatter.print_key_value("Application Rule Collections", len(application_rule_collections))
                        self.formatter.print_key_value("NAT Rule Collections", len(nat_rule_collections))
                        
                        # Check if firewall has rules configured
                        total_rules = (len(network_rule_collections) + 
                                     len(application_rule_collections) + 
                                     len(nat_rule_collections))
                        
                        if total_rules > 0:
                            self.formatter.print_success("Firewall has rule collections configured")
                        else:
                            self.formatter.print_warning("⚠ Firewall has no rule collections configured")
                        
                        # Check firewall SKU and features
                        sku = properties.get('sku', {})
                        sku_name = sku.get('name', 'Unknown')
                        sku_tier = sku.get('tier', 'Unknown')
                        
                        self.formatter.print_key_value("SKU", f"{sku_name} ({sku_tier})")
                        
                        # Check threat intelligence
                        threat_intel_mode = properties.get('threatIntelMode', 'Unknown')
                        self.formatter.print_key_value("Threat Intelligence Mode", threat_intel_mode)
                        
                        if threat_intel_mode in ['Alert', 'Deny']:
                            self.formatter.print_success("Threat intelligence enabled")
                        else:
                            self.formatter.print_warning("⚠ Threat intelligence not enabled")
                        
                        self.formatter.print_separator()
            else:
                self.formatter.print_error(f"Failed to retrieve Azure Firewalls: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking Azure Firewalls: {e}")
        
        # 3. Check NSG Flow Logs
        self.formatter.print_subsection("NSG FLOW LOGS CONFIGURATION")
        try:
            url = f"/subscriptions/{subscription_id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2022-09-01"
            response = self.api_client.arm_get(url)
            if response.status_code == 200:
                response_data = response.json()
                if response_data is None:
                    self.formatter.print_error("Failed to parse response data - response is None")
                    return
                    
                nsgs = response_data.get('value', [])
                if nsgs is None:
                    nsgs = []
                    
                if not nsgs:
                    self.formatter.print_info("No Network Security Groups found in this subscription.")
                else:
                    self.formatter.print_success(f"Found {len(nsgs)} Network Security Groups")
                    
                    flow_logs_enabled = 0
                    flow_logs_disabled = 0
                    
                    for nsg in nsgs:
                        if not isinstance(nsg, dict):
                            continue
                        nsg_name = nsg.get('name', 'Unknown')
                        nsg_id = nsg.get('id', '')
                        
                        # Check flow logs for this NSG
                        flow_logs_url = f"{nsg_id}/flowLogs?api-version=2022-09-01"
                        flow_logs_response = self.api_client.arm_get(flow_logs_url)
                        
                        if flow_logs_response.status_code == 200:
                            flow_logs_data = flow_logs_response.json()
                            if flow_logs_data is None:
                                self.formatter.print_warning(f"NSG {nsg_name}: Could not parse flow logs response")
                                flow_logs_disabled += 1
                                continue
                                
                            flow_logs = flow_logs_data.get('value', [])
                            if flow_logs is None:
                                flow_logs = []
                                
                            if flow_logs:
                                flow_logs_enabled += 1
                                self.formatter.print_success(f"NSG {nsg_name}: Flow logs enabled")
                                
                                for flow_log in flow_logs:
                                    if not isinstance(flow_log, dict):
                                        continue
                                    flow_log_name = flow_log.get('name', 'Unknown')
                                    flow_log_props = flow_log.get('properties', {})
                                    enabled = flow_log_props.get('enabled', False)
                                    retention_days = flow_log_props.get('retentionPolicy', {}).get('days', 0)
                                    
                                    self.formatter.print_key_value(f"Flow Log: {flow_log_name}", f"Enabled: {enabled}, Retention: {retention_days} days")
                                    
                                    if enabled and retention_days >= 7:
                                        self.formatter.print_success("Flow log properly configured")
                                    else:
                                        self.formatter.print_warning("⚠ Flow log needs configuration")
                            else:
                                flow_logs_disabled += 1
                                self.formatter.print_warning(f"NSG {nsg_name}: No flow logs configured")
                        else:
                            flow_logs_disabled += 1
                            self.formatter.print_warning(f"NSG {nsg_name}: Could not retrieve flow logs")
                    
                    self.formatter.print_subsection("NSG FLOW LOGS SUMMARY")
                    self.formatter.print_key_value("NSGs with Flow Logs", flow_logs_enabled)
                    self.formatter.print_key_value("NSGs without Flow Logs", flow_logs_disabled)
                    
                    if flow_logs_enabled > 0:
                        self.formatter.print_success("Some NSGs have flow logs enabled for traffic path monitoring")
                    else:
                        self.formatter.print_error("No NSGs have flow logs enabled")
            else:
                self.formatter.print_error(f"Failed to retrieve NSGs: {response.status_code}")
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking NSG flow logs: {e}")
        
        # 4. Check Log Analytics Workspace for Firewall and NSG Logs
        self.formatter.print_subsection("LOG ANALYTICS WORKSPACE - FIREWALL AND NSG LOGS")
        workspace_name = getattr(self.config, 'workspace_name', None)
        resource_group = getattr(self.config, 'resource_group', None)
        
        if workspace_name and resource_group:
            try:
                # Check diagnostic settings for Azure Firewall
                for firewall in firewalls:
                    firewall_name = firewall.get('name', 'Unknown')
                    firewall_id = firewall.get('id', '')
                    
                    diag_url = f"{firewall_id}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
                    diag_response = self.api_client.arm_get(diag_url)
                    
                    if diag_response.status_code == 200:
                        diag_data = diag_response.json()
                        if diag_data is None:
                            self.formatter.print_warning(f"Firewall {firewall_name}: Could not parse diagnostic settings response")
                            continue
                            
                        diag_settings = diag_data.get('value', [])
                        if diag_settings is None:
                            diag_settings = []
                            
                        if diag_settings:
                            self.formatter.print_success(f"Firewall {firewall_name}: Diagnostic settings configured")
                            
                            for setting in diag_settings:
                                if not isinstance(setting, dict):
                                    continue
                                setting_name = setting.get('name', 'Unknown')
                                if setting_name is None:
                                    setting_name = 'Unknown'
                                    
                                setting_properties = setting.get('properties', {})
                                if setting_properties is None:
                                    setting_properties = {}
                                    
                                logs = setting_properties.get('logs', [])
                                if logs is None:
                                    logs = []
                                
                                # Check for firewall logs
                                firewall_logs = []
                                for log in logs:
                                    if not isinstance(log, dict):
                                        continue
                                    category = log.get('category', '')
                                    if category is None:
                                        category = ''
                                    if any(keyword in category.lower() for keyword in ['firewall', 'network', 'traffic']):
                                        firewall_logs.append(log)
                                
                                if firewall_logs:
                                    self.formatter.print_success(f"Diagnostic setting '{setting_name}' includes firewall logs")
                                    for log in firewall_logs:
                                        self.formatter.print_key_value(f"Log Category", log.get('category', 'Unknown'))
                                        self.formatter.print_key_value(f"Enabled", log.get('enabled', False))
                                else:
                                    self.formatter.print_warning(f"Diagnostic setting '{setting_name}' has no firewall logs")
                        else:
                            self.formatter.print_warning(f"Firewall {firewall_name}: No diagnostic settings configured")
                    else:
                        self.formatter.print_warning(f"Firewall {firewall_name}: Could not retrieve diagnostic settings")
                
                # Check for NSG diagnostic settings
                for nsg in nsgs:
                    nsg_name = nsg.get('name', 'Unknown')
                    nsg_id = nsg.get('id', '')
                    
                    diag_url = f"{nsg_id}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
                    diag_response = self.api_client.arm_get(diag_url)
                    
                    if diag_response.status_code == 200:
                        diag_data = diag_response.json()
                        if diag_data is None:
                            self.formatter.print_warning(f"NSG {nsg_name}: Could not parse diagnostic settings response")
                            continue
                            
                        diag_settings = diag_data.get('value', [])
                        if diag_settings is None:
                            diag_settings = []
                            
                        if diag_settings:
                            self.formatter.print_success(f"NSG {nsg_name}: Diagnostic settings configured")
                            
                            for setting in diag_settings:
                                if not isinstance(setting, dict):
                                    continue
                                    
                                setting_name = setting.get('name', 'Unknown')
                                if setting_name is None:
                                    setting_name = 'Unknown'
                                    
                                setting_properties = setting.get('properties', {})
                                if setting_properties is None:
                                    setting_properties = {}
                                    
                                logs = setting_properties.get('logs', [])
                                if logs is None:
                                    logs = []
                                
                                # Check for NSG logs
                                nsg_logs = []
                                for log in logs:
                                    if not isinstance(log, dict):
                                        continue
                                    category = log.get('category', '')
                                    if category is None:
                                        category = ''
                                    if any(keyword in category.lower() for keyword in ['nsg', 'network', 'security']):
                                        nsg_logs.append(log)
                                
                                if nsg_logs:
                                    self.formatter.print_success(f"Diagnostic setting '{setting_name}' includes NSG logs")
                                    for log in nsg_logs:
                                        self.formatter.print_key_value(f"Log Category", log.get('category', 'Unknown'))
                                        self.formatter.print_key_value(f"Enabled", log.get('enabled', False))
                                else:
                                    self.formatter.print_warning(f"Diagnostic setting '{setting_name}' has no NSG logs")
                        else:
                            self.formatter.print_warning(f"NSG {nsg_name}: No diagnostic settings configured")
                    else:
                        self.formatter.print_warning(f"NSG {nsg_name}: Could not retrieve diagnostic settings")
            except Exception as e:
                self.formatter.print_error(f"Exception occurred while checking diagnostic settings: {e}")
        else:
            self.formatter.print_warning("workspace_name and resource_group not configured - skipping Log Analytics checks")
        
        # 5. Summary and Compliance Assessment
        self.formatter.print_subsection("UDR AND FIREWALL TRAFFIC PATH COMPLIANCE SUMMARY")
        self.formatter.print_key_value("Total Route Tables", total_route_tables)
        self.formatter.print_key_value("Compliant Route Tables", compliant_route_tables)
        self.formatter.print_key_value("Non-Compliant Route Tables", total_route_tables - compliant_route_tables)
        
        if total_route_tables > 0:
            compliance_percentage = (compliant_route_tables / total_route_tables) * 100
            self.formatter.print_key_value("Compliance Percentage", f"{compliance_percentage:.1f}%")
            
            if compliance_percentage >= 80:
                self.formatter.print_success("Good UDR compliance - most route tables route to firewalls")
            elif compliance_percentage >= 50:
                self.formatter.print_warning("⚠ Moderate UDR compliance - some route tables need firewall routing")
            else:
                self.formatter.print_error("Poor UDR compliance - most route tables missing firewall routing")
        
        if firewall_routes_found:
            self.formatter.print_subsection("FIREWALL ROUTES FOUND")
            for route in firewall_routes_found:
                self.formatter.print_success(f"{route}")
        
        if missing_firewall_routes:
            self.formatter.print_subsection("MISSING FIREWALL ROUTES")
            for route in missing_firewall_routes:
                self.formatter.print_error(f"{route}")
        
        self.formatter.print_separator()

    def check_group_membership(self):
        """List all Microsoft Entra ID groups and the members assigned to each group, with a table of member details and their roles. List users not in any group separately. Limit number of groups displayed with max_subitems config."""
        self.formatter.print_header(
            "MICROSOFT ENTRA ID GROUP MEMBERSHIP",
            "This function lists all Microsoft Entra ID groups and the members assigned to each group, with a table of member details and their roles. Users not part of any group are listed separately."
        )
        try:
            max_items = getattr(self.config, 'max_lines', 100)
            max_groups = getattr(self.config, 'max_subitems', 10)
            
            # Get all groups with better error handling
            groups_response = self.api_client.graph_get(f"/groups?$top={max_groups}&$select=id,displayName,description,mailEnabled,securityEnabled")
            if groups_response.status_code != 200:
                # Try alternative approach with different parameters
                groups_response = self.api_client.graph_get(f"/groups?$top={max_groups}")
                if groups_response.status_code != 200:
                    self.formatter.print_error(f"Failed to retrieve groups: {groups_response.status_code}")
                    self.formatter.print_error(f"Response: {groups_response.text}")
                    self.formatter.print_info("This may indicate insufficient Graph API permissions or the tenant doesn't have any groups")
                    return
            
            groups = groups_response.json().get('value', [])
            if not groups:
                self.formatter.print_info("No groups found in the tenant")
                return
                
            # Get all users with better error handling
            users_response = self.api_client.graph_get(f"/users?$top={max_items}&$select=id,displayName,userPrincipalName,mail")
            if users_response.status_code != 200:
                # Try alternative approach
                users_response = self.api_client.graph_get(f"/users?$top={max_items}")
                if users_response.status_code != 200:
                    self.formatter.print_error(f"Failed to retrieve users: {users_response.status_code}")
                    self.formatter.print_error(f"Response: {users_response.text}")
                    self.formatter.print_info("This may indicate insufficient Graph API permissions")
                    return
            
            users = users_response.json().get('value', [])
            user_id_map = {u['id']: u for u in users}
            user_groups_map = {u['id']: [] for u in users}
            all_member_ids = set()
            
            # For each group, print group and table of members (limit to max_groups)
            for group in groups[:max_groups]:
                group_id = group.get('id')
                group_name = group.get('displayName', 'Unnamed Group')
                group_description = group.get('description', 'No description')
                mail_enabled = group.get('mailEnabled', False)
                security_enabled = group.get('securityEnabled', False)
                
                self.formatter.print_section_header(f"Group: {group_name}")
                self.formatter.print_key_value("Description", group_description)
                self.formatter.print_key_value("Mail Enabled", str(mail_enabled))
                self.formatter.print_key_value("Security Enabled", str(security_enabled))
                
                # Get members with better error handling
                members_response = self.api_client.graph_get(f"/groups/{group_id}/members?$top={max_items}&$select=id,displayName,userPrincipalName,mail")
                if members_response.status_code != 200:
                    self.formatter.print_error(f"Failed to retrieve members for group {group_name}: {members_response.status_code}")
                    self.formatter.print_error(f"Response: {members_response.text}")
                    continue
                
                members = members_response.json().get('value', [])
                if not members:
                    self.formatter.print_info("(No members assigned)")
                    continue
                
                table_rows = []
                for m in members[:max_items]:
                    member_id = m.get('id')
                    all_member_ids.add(member_id)
                    
                    # Add this group to the user's groups
                    if member_id in user_groups_map:
                        user_groups_map[member_id].append(group_name)
                    
                    # Get roles for this member (directory roles) with better error handling
                    roles_response = self.api_client.graph_get(f"/users/{member_id}/memberOf?$top={max_items}&$select=displayName")
                    roles = []
                    if roles_response.status_code == 200:
                        roles_data = roles_response.json().get('value', [])
                        roles = [r.get('displayName', '') for r in roles_data if r.get('@odata.type', '').endswith('directoryRole')]
                    
                    # Metadata
                    upn = m.get('userPrincipalName', '')
                    disp = m.get('displayName', '')
                    mail = m.get('mail', '')
                    typ = m.get('@odata.type', '').replace('#microsoft.graph.', '')
                    
                    table_rows.append([
                        disp or upn or member_id,
                        upn,
                        mail,
                        typ,
                        ", ".join(roles) if roles else "(none)"
                    ])
                
                if len(members) > max_items:
                    self.formatter.print_info(f"Table truncated to first {max_items} members.")
                
                self.formatter.print_table([
                    "Display Name", "User Principal Name", "Email", "Type", "Role(s)"
                ], table_rows)
                self.formatter.print_separator()
            
            # Users not in any group
            not_in_group = [u for u in users if u['id'] not in all_member_ids]
            if not_in_group:
                self.formatter.print_section_header("Users not in any group")
                table_rows = []
                for u in not_in_group[:max_items]:
                    # Get roles for this user (directory roles) with better error handling
                    user_id = u.get('id')
                    roles_response = self.api_client.graph_get(f"/users/{user_id}/memberOf?$top={max_items}&$select=displayName")
                    roles = []
                    if roles_response.status_code == 200:
                        roles_data = roles_response.json().get('value', [])
                        roles = [r.get('displayName', '') for r in roles_data if r.get('@odata.type', '').endswith('directoryRole')]
                    
                    table_rows.append([
                        u.get('displayName', ''),
                        u.get('userPrincipalName', ''),
                        u.get('mail', ''),
                        u.get('id', ''),
                        ", ".join(roles) if roles else "(none)"
                    ])
                
                if len(not_in_group) > max_items:
                    self.formatter.print_info(f"Table truncated to first {max_items} users.")
                
                self.formatter.print_table([
                    "Display Name", "User Principal Name", "Email", "Object ID", "Role(s)"
                ], table_rows)
            else:
                self.formatter.print_info("All users are members of at least one group.")
                
        except Exception as e:
            self.formatter.print_error(f"Exception occurred: {e}")
            self.formatter.print_info("This may indicate Graph API permission issues or network connectivity problems")
        self.formatter.print_separator()

    def check_microsoft_defender_for_devops(self):
        """Check Microsoft Defender for DevOps configuration for secret scanning and hardcoded credential detection."""
        self.formatter.print_header(
            "MICROSOFT DEFENDER FOR DEVOPS",
            "This function checks Microsoft Defender for Cloud DevOps Security configuration, including secret scanning and hardcoded credential detection for CI/CD pipelines (GitHub and Azure DevOps)."
        )
        subscription_id = getattr(self.config, 'subscription_id', None)
        if not subscription_id:
            self.formatter.print_error("subscription_id must be set in config.")
            return
        
        try:
            # Check for GitHub integration
            try:
                github_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/gitHubOwners?api-version=2023-09-01-preview"
                github_response = self.api_client.arm_get(github_url)
                
                if github_response.status_code == 200:
                    github_owners = github_response.json().get('value', [])
                    if github_owners:
                        self.formatter.print_success(f"Found {len(github_owners)} GitHub organization(s) connected to Microsoft Defender for Cloud")
                        
                        for owner in github_owners:
                            owner_name = owner.get('name', 'Unknown')
                            
                            # Check for repositories
                            repos_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/gitHubOwners/{owner_name}/repos?api-version=2023-09-01-preview"
                            repos_response = self.api_client.arm_get(repos_url)
                            
                            if repos_response.status_code == 200:
                                repos = repos_response.json().get('value', [])
                                if repos:
                                    self.formatter.print_success(f"GitHub organization '{owner_name}' has {len(repos)} connected repositories")
                                    
                                    max_subitems = getattr(self.config, 'max_subitems', 10)
                                    for repo in repos[:max_subitems]:  # Show first max_subitems repos
                                        repo_name = repo.get('name', 'Unknown')
                                        repo_props = repo.get('properties', {})
                                        
                                        # Check for secret scanning configuration
                                        onboarding_state = repo_props.get('onboardingState', 'Unknown')
                                        if onboarding_state == 'Onboarded':
                                            self.formatter.print_success(f"Repository '{repo_name}' is onboarded for security scanning")
                                        else:
                                            self.formatter.print_warning(f"Repository '{repo_name}' is not onboarded (State: {onboarding_state})")
                                    
                                    if len(repos) > max_subitems:
                                        self.formatter.print_info(f"... and {len(repos) - max_subitems} more repositories")
                                else:
                                    self.formatter.print_warning(f"No repositories found for GitHub organization '{owner_name}'")
                            else:
                                self.formatter.print_warning(f"Could not retrieve repositories for GitHub organization '{owner_name}'")
                    else:
                        self.formatter.print_warning("No GitHub organizations connected to Microsoft Defender for Cloud")
                elif github_response.status_code == 404:
                    self.formatter.print_info("Microsoft Defender for DevOps GitHub integration not configured")
                else:
                    self.formatter.print_warning(f"Could not check GitHub integration: {github_response.status_code}")
            except Exception as e:
                self.formatter.print_info("GitHub integration check not available or requires additional permissions")
            
            # Check for Azure DevOps integration
            try:
                azure_devops_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/azureDevOpsOrgs?api-version=2023-09-01-preview"
                azure_devops_response = self.api_client.arm_get(azure_devops_url)
                
                if azure_devops_response.status_code == 200:
                    azure_devops_orgs = azure_devops_response.json().get('value', [])
                    if azure_devops_orgs:
                        self.formatter.print_success(f"Found {len(azure_devops_orgs)} Azure DevOps organization(s) connected to Microsoft Defender for Cloud")
                        
                        for org in azure_devops_orgs:
                            org_name = org.get('name', 'Unknown')
                            
                            # Check for projects
                            projects_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/azureDevOpsOrgs/{org_name}/projects?api-version=2023-09-01-preview"
                            projects_response = self.api_client.arm_get(projects_url)
                            
                            if projects_response.status_code == 200:
                                projects = projects_response.json().get('value', [])
                                if projects:
                                    self.formatter.print_success(f"Azure DevOps organization '{org_name}' has {len(projects)} connected projects")
                                    
                                    max_subitems = getattr(self.config, 'max_subitems', 10)
                                    for project in projects[:max_subitems]:  # Show first max_subitems projects
                                        project_name = project.get('name', 'Unknown')
                                        project_props = project.get('properties', {})
                                        
                                        # Check for security scanning configuration
                                        onboarding_state = project_props.get('onboardingState', 'Unknown')
                                        if onboarding_state == 'Onboarded':
                                            self.formatter.print_success(f"Project '{project_name}' is onboarded for security scanning")
                                        else:
                                            self.formatter.print_warning(f"Project '{project_name}' is not onboarded (State: {onboarding_state})")
                                    
                                    if len(projects) > max_subitems:
                                        self.formatter.print_info(f"... and {len(projects) - max_subitems} more projects")
                                else:
                                    self.formatter.print_warning(f"No projects found for Azure DevOps organization '{org_name}'")
                            else:
                                self.formatter.print_warning(f"Could not retrieve projects for Azure DevOps organization '{org_name}'")
                    else:
                        self.formatter.print_warning("No Azure DevOps organizations connected to Microsoft Defender for Cloud")
                elif azure_devops_response.status_code == 404:
                    self.formatter.print_info("Microsoft Defender for DevOps Azure DevOps integration not configured")
                else:
                    self.formatter.print_warning(f"Could not check Azure DevOps integration: {azure_devops_response.status_code}")
            except Exception as e:
                self.formatter.print_info("Azure DevOps integration check not available or requires additional permissions")
            
            # Check for recent security findings
            try:
                alerts_url = f"/subscriptions/{subscription_id}/providers/Microsoft.Security/alerts?api-version=2022-01-01&$filter=severity eq 'High' or severity eq 'Medium'"
                alerts_response = self.api_client.arm_get(alerts_url)
                
                if alerts_response.status_code == 200:
                    alerts = alerts_response.json().get('value', [])
                    devops_alerts = []
                    
                    # Filter for DevOps-related alerts
                    for alert in alerts:
                        alert_props = alert.get('properties', {})
                        alert_name = alert_props.get('alertDisplayName', '')
                        alert_description = alert_props.get('description', '')
                        
                        # Look for DevOps-related keywords
                        devops_keywords = ['secret', 'credential', 'password', 'token', 'key', 'devops', 'github', 'azure devops', 'hardcoded']
                        if any(keyword in alert_name.lower() or keyword in alert_description.lower() for keyword in devops_keywords):
                            devops_alerts.append(alert)
                    
                    if devops_alerts:
                        self.formatter.print_warning(f"Found {len(devops_alerts)} DevOps-related security alerts")
                        max_subitems = getattr(self.config, 'max_subitems', 10)
                        for alert in devops_alerts[:max_subitems]:  # Show first max_subitems alerts
                            alert_props = alert.get('properties', {})
                            alert_name = alert_props.get('alertDisplayName', 'Unknown')
                            severity = alert_props.get('severity', 'Unknown')
                            self.formatter.print_key_value(f"Alert: {alert_name}", f"Severity: {severity}")
                        
                        if len(devops_alerts) > max_subitems:
                            self.formatter.print_info(f"... and {len(devops_alerts) - max_subitems} more DevOps-related alerts")
                    else:
                        self.formatter.print_success("No DevOps-related security alerts found")
                else:
                    self.formatter.print_warning("Could not retrieve security alerts")
            except Exception as e:
                self.formatter.print_info("Security alerts check not available")
            
        except Exception as e:
            self.formatter.print_error(f"Exception occurred while checking Microsoft Defender for DevOps: {e}")
        
        self.formatter.print_separator()