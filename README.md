# Security Policy Printer v3 - Microsoft Entra ID Security Policies Configuration Retriever

## Purpose

This script serves as evidence that security requirements have been fulfilled by printing the current configurations of relevant Microsoft Entra ID (Azure AD) security policies and Azure resource configurations. It is designed to support FedRAMP Moderate compliance assessments by providing automated evidence gathering for various security controls.

The script retrieves configuration data from Microsoft Graph API and Azure Resource Manager (ARM) API to validate that security policies are properly configured and enforced across your Azure environment. Version 3 introduces enhanced audit record capabilities and comprehensive non-repudiation evidence collection.

## Key Features in v3

- **Enhanced Audit Record Collection**: Comprehensive audit records with all required non-repudiation attributes
- **Microsoft Sentinel Integration**: Advanced monitoring of administrative actions, query auditing, and command execution
- **Token Management**: Automated token refresh and management system
- **Modular Architecture**: Separated concerns with dedicated modules for different functionality
- **Comprehensive Output**: Detailed evidence collection with formatted output for compliance reporting

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
  "max_lines": 100,
  "output_file": "out.txt",
  "tenant_id": "your-tenant-id",
  "client_id": "your-client-id",
  "client_secret": "your-client-secret"
}
```

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
- Adjust the `max_lines` parameter in config to control output verbosity

## 1. The script currently reads and logs the configurations of the following controls and policies:

### Authentication and Access Controls
- Smart Lockout Defaults
- Custom Smart Lockout (Password Protection)
- Conditional Access Policies (Device Compliance, MFA)
- Intune Machine Inactivity Limit (Auto-Lock)
- Available Permissions
- Intune Compliance Policies (BitLocker, Defender, Secure Boot, Password)

### Sentinel and Monitoring
- Sentinel Error Analytic Rules
- Sentinel Defender Connector Status
- Sentinel Defender Endpoint Connector Status
- Sentinel Incident Summary
- Sentinel Log Deletion Alert Rules
- Recent Sentinel Error Logs
- **Microsoft Sentinel Privileged Command Auditing** (NEW in v3)
- **Microsoft Sentinel Comprehensive Audit Records** (NEW in v3)

### Defender and Security
- Defender for Cloud Failed Checks
- Defender FIM Configuration
- Defender App Control Status
- Defender Endpoint Malware Protection

### Network Security
- WAF Deployment and Policy Status
- DNSSEC Status
- NSG SMTP Block Status
- Firewall SMTP Block Status
- Bastion SSH Timeout Status

### Infrastructure and Compliance
- Admin Group Membership
- Blob Storage ZRS Status
- Recovery Services Backup Policies
- Missing Asset Tag Resources
- Log Analytics Immutability
- PIM Role Assignment Policies
- Intune Device Compliance Details
- Certificate Compliance Evidence
- Master Inventory Reconciliation
- Infrastructure Vulnerability Scans
- Insider Threat Escalation

### Risk-Based Security
- User Risk Policy
- Identity Protection Risk Detections
- Sign-in Risk Policy

### Infrastructure and Monitoring
- Bastion Host Settings
- Encryption Policy and Defender Status
- Log Analytics Retention Settings
- Workspace RBAC
- Credential Distribution Audit Events
- CIS L1 Initiative Assignment
- WAF Diagnostic Settings
- Recent FIM Alerts
- ARM Template Configuration Orchestration
- **Recent Sentinel Security Alerts** (ENHANCED in v3)

### Advanced Security Controls
- Intrusion Detection Systems
- Logical Access Review
- Logical Access Revocation
- Screen Lock Obfuscation Settings

## 2 (a). Required Microsoft Graph API Permissions

For the script to function correctly, your Azure AD application must have the following 
Microsoft Graph API permissions (Application permissions):

- Policy.Read.All
- Directory.Read.All
- IdentityRiskyUser.Read.All
- IdentityRiskEvent.Read.All
- DeviceManagementConfiguration.Read.All
- DeviceManagementManagedDevices.Read.All
- RoleManagement.Read.Directory
- User.Read.All
- Group.Read.All
- AuditLog.Read.All
- SecurityEvents.Read.All
- SecurityIncident.Read.All

All of the above must be added as **Application** permissions (not Delegated), and you must grant admin consent in the Azure portal after adding them.

## 2 (b). Required Azure Resource Manager (ARM) Permissions

For the script to retrieve Azure resource configurations, your Azure AD application (service principal) must be assigned the following Azure RBAC role at the **subscription** or **resource group** level:

- **Reader** (built-in role)

This role grants read-only access to all resources, which is sufficient for all the ARM API requests made by the script.

## 3. API Endpoints Used

The script uses the following API endpoints:

### Microsoft Graph API Endpoints:
- /policies/identitySecurityDefaultsEnforcementPolicy
- /directorySettings
- /deviceManagement/deviceConfigurations
- /deviceManagement/deviceCompliancePolicies
- /identity/conditionalAccess/policies
- /identityProtection/userRiskPolicy
- /identityProtection/riskDetections
- /roleManagement/directory/roleAssignmentSchedulePolicies
- /domains
- /directoryRoles
- /deviceManagement/managedDevices
- /policies/authenticationMethodsPolicy
- /policies
- /security/secureScoreControlProfiles
- /security/alerts
- /identityGovernance/lifecycleWorkflows/workflows
- /identityGovernance/accessReviews/definitions
- /auditLogs/directoryAudits (with various filters)
- /groups
- /identityGovernance/accessReviews/definitions/{reviewId}/instances

### Azure Resource Manager (ARM) API Endpoints:
- /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Network/bastionHosts
- /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyAssignments
- /subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings
- /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}
- /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.Authorization/roleAssignments
- /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/alertRules
- /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/incidents
- /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/dataConnectors
- /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups
- /subscriptions/{subscriptionId}/providers/Microsoft.Network/azureFirewalls
- /subscriptions/{subscriptionId}/providers/Microsoft.CertificateManager/certificateManagers
- /subscriptions/{subscriptionId}/providers/Microsoft.CertificateManager/certificates
- /subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults
- /subscriptions/{subscriptionId}/providers/Microsoft.Network/dnsZones
- /subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts
- /subscriptions/{subscriptionId}/providers/Microsoft.RecoveryServices/vaults
- /subscriptions/{subscriptionId}/resources
- /subscriptions/{subscriptionId}/providers/Microsoft.Resources/deployments
- /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments
- /subscriptions/{subscriptionId}/providers/Microsoft.Security/alerts
- /subscriptions/{subscriptionId}/providers/Microsoft.Web/certificates
- /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.RecoveryServices/vaults/{vaultName}/backupPolicies

### Log Analytics Query API:
- /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/api/query

## 4. Project Structure

```
SecurityPolicyPrinter_v3/
├── main.py                 # Main entry point and orchestration
├── security_functions.py   # All security policy check functions
├── helpers.py             # Configuration, API client, and formatting utilities
├── token_manager.py       # Token management and refresh functionality
├── config.json            # Environment configuration
├── access_tokens.json     # Cached access tokens (auto-generated)
├── out.txt               # Output file (auto-generated)
└── README.md             # This file
```

## 5. New Features in v3

### Enhanced Audit Record Collection
The new `check_sentinel_comprehensive_audit_records()` function provides comprehensive audit records with all required non-repudiation attributes:

- **Sentinel Administrative Actions**: Tracks all administrative operations on Sentinel resources
- **Log Analytics Query Auditing**: Monitors all queries executed against the workspace
- **Windows Command Execution**: Captures detailed process creation events
- **Non-repudiation Verification**: Explicitly maps all required attributes to data sources

### Improved Token Management
- Automatic token refresh and caching
- Centralized token management in `TokenManager` class
- Seamless integration with Azure Identity library

### Modular Architecture
- Separated concerns across multiple modules
- Reusable components for API interactions
- Centralized configuration management

### Enhanced Output Formatting
- Consistent formatting across all functions
- Clear success/failure indicators
- Detailed evidence collection for compliance reporting

## 6. Compliance Evidence

This tool provides comprehensive evidence for FedRAMP Moderate compliance by:

- **Non-repudiation**: Full audit trails with complete command and query recording
- **Access Control**: Verification of authentication and authorization policies
- **Monitoring**: Evidence of security monitoring and alerting capabilities
- **Configuration Management**: Validation of security policy configurations
- **Incident Response**: Documentation of security incident handling capabilities

## 7. Troubleshooting

### Common Issues

1. **Token Expiration**: The script automatically handles token refresh. If you encounter authentication errors, check your Azure AD application permissions.

2. **Permission Errors**: Ensure your service principal has the Reader role assigned at the subscription or resource group level.

3. **Missing Data**: Some functions may return no results if the corresponding services are not configured or if no relevant data exists in the specified time period.

4. **API Rate Limits**: The script includes error handling for API rate limits and will retry requests as appropriate.

### Debug Mode

To enable detailed error logging, modify the configuration to increase verbosity or check the console output for detailed error messages.

## 8. Contributing

When adding new security checks:

1. Follow the existing pattern in `security_functions.py`
2. Use the provided `APIClient` for API calls
3. Use the `Formatter` class for consistent output
4. Add appropriate error handling
5. Update this README with new functionality

## 9. Version History

- **v3.0**: Enhanced audit record collection, modular architecture, improved token management
- **v2.0**: Additional security controls and improved error handling
- **v1.0**: Initial release with basic security policy checks

## 10. License

This project is designed for internal compliance and security assessment purposes. Please ensure compliance with your organization's security policies when using this tool. 