# Security Policy Printer v3 - Microsoft Entra ID Security Policies Configuration Retriever

## Purpose

This script serves as evidence that security requirements have been fulfilled by printing the current configurations of relevant Microsoft Entra ID (Azure AD) security policies and Azure resource configurations. It is designed to support FedRAMP Moderate compliance assessments by providing automated evidence gathering for various security controls.

The script retrieves configuration data from Microsoft Graph API and Azure Resource Manager (ARM) API to validate that security policies are properly configured and enforced across your Azure environment.

## How to Use

### Prerequisites
1. **Azure AD Application Registration**: Create an app registration in Azure AD with the required permissions (see section 2 below)
2. **Configuration Setup**: Configure your environment settings in `config.json`
3. **Python Environment**: Ensure Python 3.6+ is installed with the required libraries

### Setup Steps

#### 1. Configure Environment Settings

Create or update the `config.json` file with your Azure environment details:

```json
{
  "subscription_id": "your-subscription-id",
  "resource_group": "your-resource-group", 
  "workspace_name": "your-log-analytics-workspace",
  "graph_base_url": "https://graph.microsoft.com/v1.0",
  "arm_base_url": "https://management.azure.com",
  "max_items": 10,
  "max_subitems": 10,
  "output_file": "out.txt",
  "tenant_id": "your-tenant-id",
  "client_id": "your-client-id",
  "client_secret": "your-client-secret"
}
```

**Required Configuration Fields:**
- `subscription_id`: Azure subscription ID
- `resource_group`: Resource group containing Log Analytics workspace
- `workspace_name`: Log Analytics workspace name
- `tenant_id`: Azure AD tenant ID
- `client_id`: Azure AD app registration client ID
- `client_secret`: Azure AD app registration client secret

**Optional Configuration Fields:**
- `max_items`: Maximum number of items to display (default: 10)
- `max_subitems`: Maximum number of sub-items to display (default: 10)
- `output_file`: Output file name (default: "out.txt")

#### 2. Install Dependencies

Install the required Python packages:

```bash
pip install requests azure-identity
```

#### 3. Run the Main Script

```bash
python main.py
```

The script will automatically:
- Load configuration from `config.json`
- Obtain and refresh access tokens as needed
- Execute all security policy checks
- Output results to both console and the specified output file

### Output
- The script outputs results to both console and the configured output file
- Each control assessment includes:
  - ✓ Success indicators for properly configured controls
  - ✗ Failure indicators for missing or misconfigured controls
  - ⚠️ Warning indicators for potential compliance gaps
  - Detailed configuration information and recommendations

### Customization
- Modify `config.json` to adjust workspace settings and output preferences
- Comment/uncomment specific function calls in `main.py` to run only desired assessments
- Adjust the `max_items` and `max_subitems` parameters in config to control output verbosity

## 1. The script currently reads and logs the configurations of the following controls and policies:

### Authentication and Access Controls
- Smart Lockout Defaults and Custom Settings
- Password Protection Policy
- Conditional Access Policies (Device Compliance, MFA, Mobile Device Blocking)
- Intune Machine Inactivity Limit (Auto-Lock)
- Available Permissions Check
- Intune Compliance Policies (BitLocker, Defender, Secure Boot, Password)
- Users Must Change Password Policy

### Sentinel and Monitoring
- Sentinel Error Analytic Rules
- Sentinel Defender Connector Status
- Sentinel Defender Endpoint Connector Status
- Sentinel Connected Workspaces
- Sentinel Incident Summary
- Sentinel Log Deletion Alert Rules
- Recent Sentinel Error Logs (24 hours)
- Microsoft Sentinel Privileged Command Auditing
- Microsoft Sentinel Comprehensive Audit Records
- Sentinel System Performance Monitoring
- Sentinel Alerts and Health Reports
- Recent Sentinel Security Alerts (24 hours)
- Recent Security Incidents

### Defender and Security
- Defender for Cloud Failed Checks
- Defender FIM Configuration
- Defender App Control Status
- Defender Endpoint Malware Protection
- Defender Cloud Security Posture Management

### Network Security
- WAF Deployment and Policy Status
- DNSSEC Status
- NSG SMTP Block Status (Ports 25, 465)
- Firewall SMTP Block Status (Ports 25, 465)
- Bastion SSH Timeout Status
- P2P File Sharing Restriction
- ASG Boundary Protection
- Inbound Internet Traffic Restriction
- ASG Non-Secure Protocol Restriction
- Bastion Host Settings
- NSG Allowed/Disallowed Ports

### Infrastructure and Compliance
- Admin Group Membership
- Blob Storage Audit Retention
- FIPS Validated Encryption
- Recovery Services Backup Policies
- Comprehensive Database Backup Status
- Missing Asset Tag Resources
- Log Analytics Immutability
- PIM Role Assignment Policies
- Intune Device Compliance Details
- Certificate Compliance Evidence
- Master Inventory Reconciliation
- Infrastructure Vulnerability Scans
- Insider Threat Escalation
- Azure Functions Multi-AZ
- Azure Time Sync Service
- High Availability and RTO
- Azure Posture Management Deployment Logs
- Azure Functions Availability Zones

### Risk-Based Security
- User Risk Policy
- Identity Protection Risk Detections
- Sign-in Risk Policy
- High Risk Users with Activity

### Privileged Access & Identity
- PIM Admin Access
- All PIM Admins

### Advanced Security Controls
- Intrusion Detection Systems
- Logical Access Review
- Logical Access Revocation
- Screen Lock Obfuscation Settings

### Access & Session Controls
- SSH MFA Enforcement
- SSH Alerts to Teams
- VM OS Auth on Unlock

### Log Analytics and RBAC
- Log Analytics Retention Settings
- Workspace RBAC
- Credential Distribution Audit Events
- CIS L1 Initiative Assignment
- WAF Diagnostic Settings
- Recent FIM Alerts
- ARM Template Configuration Orchestration
- Log Analytics Purge Users
- Resource Groups and System Load

## 2 (a). Required Microsoft Graph API Permissions

For the script to function correctly, your Azure AD application must have the following 
Microsoft Graph API permissions (Application permissions):

- `Policy.Read.All`
- `Directory.Read.All`
- `IdentityRiskyUser.Read.All`
- `IdentityRiskEvent.Read.All`
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementManagedDevices.Read.All`
- `RoleManagement.Read.Directory`
- `User.Read.All`
- `Group.Read.All`
- `AuditLog.Read.All`
- `SecurityEvents.Read.All`
- `SecurityIncident.Read.All`
- `AccessReview.Read.All`
- `PrivilegedAccess.Read.AzureAD`
- `LifecycleWorkflows.Read.All`

All of the above must be added as **Application** permissions (not Delegated), and you must grant admin consent in the Azure portal after adding them.

## 2 (b). Required Azure Resource Manager (ARM) Permissions

For the script to retrieve Azure resource configurations, your Azure AD application (service principal) must be assigned the following Azure RBAC role at the **subscription** or **resource group** level:

- **Reader** (built-in role)

This role grants read-only access to all resources, which is sufficient for all the ARM API requests made by the script.

## 3. API Endpoints Used

The script uses the following API endpoints:

### Microsoft Graph API Endpoints:
- `/policies/identitySecurityDefaultsEnforcementPolicy`
- `/policies/authenticationMethodsPolicy`
- `/identity/conditionalAccess/policies`
- `/deviceManagement/deviceConfigurations`
- `/deviceManagement/deviceCompliancePolicies`
- `/deviceManagement/managedDevices`
- `/identityProtection/userRiskPolicy`
- `/identityProtection/riskDetections`
- `/roleManagement/directory/roleAssignmentSchedulePolicies`
- `/domains`
- `/domains/{domainId}/authenticationConfiguration`
- `/groups`
- `/users`
- `/groups/{groupId}/members`
- `/users/{userId}/memberOf`
- `/identityGovernance/lifecycleWorkflows/workflows`
- `/identityGovernance/accessReviews/definitions`
- `/identityGovernance/accessReviews/definitions/{reviewId}/instances`
- `/auditLogs/directoryAudits` (with various filters)

### Azure Resource Manager (ARM) API Endpoints:
- `/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Network/azureFirewalls`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Network/applicationSecurityGroups`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Network/bastionHosts`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Network/dnsZones`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Network/applicationGateways`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Network/frontDoors`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts/{accountName}/blobServices`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts/{accountName}/blobServices/default/containers`
- `/subscriptions/{subscriptionId}/providers/Microsoft.RecoveryServices/vaults`
- `/subscriptions/{subscriptionId}/providers/Microsoft.RecoveryServices/vaults/{vaultName}/backupPolicies`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Sql/servers`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Sql/servers/{serverName}/databases`
- `/subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults`
- `/subscriptions/{subscriptionId}/providers/Microsoft.CertificateManager/certificates`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings`
- `/subscriptionId}/providers/Microsoft.Security/assessments`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Security/alerts`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Web/certificates`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Resources/deployments`
- `/subscriptions/{subscriptionId}/resources`
- `/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyAssignments`
- `/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}`
- `/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/alertRules`
- `/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/incidents`
- `/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/dataConnectors`
- `/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.Authorization/roleAssignments`
- `/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/api/query`

### Log Analytics Query API:
- `/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/api/query`

## 4. Project Structure

```
SecurityPolicyPrinter/
├── main.py                 # Main entry point and orchestration
├── security_functions.py   # All security policy check functions
├── helpers.py             # Configuration, API client, and formatting utilities
├── token_manager.py       # Token management and refresh functionality
├── config.json            # Environment configuration
├── access_tokens.json     # Cached access tokens (auto-generated)
├── out.txt               # Output file (auto-generated)
└── README.md             # This file
```

## 5. Troubleshooting

### Common Issues

1. **Token Expiration**: The script automatically handles token refresh. If you encounter authentication errors, check your Azure AD application permissions.

2. **Permission Errors**: Ensure your service principal has the Reader role assigned at the subscription or resource group level.

3. **Missing Data**: Some functions may return no results if the corresponding services are not configured or if no relevant data exists in the specified time period.

4. **API Rate Limits**: The script includes error handling for API rate limits and will retry requests as appropriate.

5. **403 Errors**: If you encounter 403 errors for specific functions, ensure the required Microsoft Graph API permissions are granted and admin consent is provided.

## 6. Contributing

When adding new security checks:

1. Follow the existing pattern in `security_functions.py`
2. Use the provided `APIClient` for API calls
3. Use the `Formatter` class for consistent output
4. Add appropriate error handling
5. Update this README with new functionality

## 7. License

This project is designed for internal compliance and security assessment purposes. Please ensure compliance with your organization's security policies when using this tool. 