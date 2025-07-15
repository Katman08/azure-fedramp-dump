=========================================================================================
1. The script currently reads and logs the configurations of the following controls and policies:
=========================================================================================
- Smart Lockout Defaults
- Custom Smart Lockout (Password Protection)
- Intune Machine Inactivity Limit (Auto-Lock)
- Intune Compliance Policies (BitLocker, Defender, Secure Boot, Password)
- Conditional Access Policies (Device Compliance, MFA)
- User Risk Policy (Identity Protection)
- Identity Protection Risk Detections (requires Microsoft Entra ID P2)
- Sign-in Risk Detections (requires Microsoft Entra ID P2)
- Azure Bastion Host Configuration (concurrent sessions, security settings)
- Azure Bastion Host SSH Session Timeout (idle timeout enforcement for SSH sessions)
- Log Analytics Workspace Retention and Immutability Settings
- Diagnostic Settings for Error Log Forwarding (per resource)
- Log Analytics Workspace RBAC (access control)
- Sentinel Analytic Rules for Error Logs
- Sentinel Incident Summary (status, owner, investigation notes, response metrics)
- Defender for Endpoint File Integrity Monitoring Configuration
- Sentinel Defender for Endpoint Connector Status
- Recent File Integrity Monitoring Alerts
- NSG SMTP Block Check (evidence of explicit deny rules for inbound SMTP ports 25/465 in all Network Security Groups)
- Azure Firewall SMTP Block Check (evidence of explicit deny rules for inbound SMTP ports 25/465 in all Azure Firewalls)
- Infrastructure Vulnerability Scans (Azure Posture Management configuration, vulnerability assessment capabilities, scan results tracking)
- Insider Threat Escalation (Microsoft Sentinel UEBA configuration, high-risk user monitoring, insider threat detection capabilities)
- Intrusion Detection Systems (Microsoft Defender for Cloud integration with Microsoft Sentinel, data connector configuration, alert ingestion)
- Logical Access Review (Microsoft Entra ID Identity Governance access reviews, recurring review configurations, automatic user removal settings)
- Logical Access Revocation (automated offboarding processes, credential revocation tracking, 24-hour compliance monitoring)
- Microsoft Graph API Permissions Check (available permissions validation and troubleshooting)
- Microsoft Entra Password Protection Policy (banned password list and minimum length settings)
- Azure Policy Assignments and Defender for Cloud Status (policy-based security controls and cloud workload protection)
- CIS L1 Initiative Assignment Check (CIS security benchmarks compliance)
- Defender for Cloud Failed Configuration Checks (security posture assessment and gap identification)
- Azure WAF Deployment and Policy Status (web application firewall configuration and policy enforcement)
- Azure WAF Diagnostic Settings (WAF logging and monitoring configuration)
- Azure DNSSEC Status for DNS Zones (DNS integrity and protection against spoofing)
- Sentinel Defender for Cloud Connector Status (cloud security alerts integration with Sentinel)
- Microsoft Entra ID Administrative Group Membership (directory roles and administrative privileges)
- Azure Blob Storage Zone-Redundant Status (backup durability and resilience across availability zones)
- Azure Recovery Services Vaults and Backup Policies (automated backup and recovery processes)
- Azure Resources Missing AssetTag (asset management and tagging policy enforcement)
- Configuration Orchestration: ARM Templates (baseline configuration validation and deployment approvals)
- Defender Application Control (MDAC) Policy Status (application whitelisting and control)
- Log Analytics Workspace Immutability Settings (log data protection against tampering)
- Sentinel Analytic Rules for Log Deletion Alerts (log integrity and retention compliance)
- Microsoft Entra PIM Role Assignment Policies (privileged access management and assignment policies)
- Microsoft Intune Device Compliance Policy Details (detailed compliance settings across platforms)
- Certificate Compliance Evidence: Approved Certificate Authorities (SSL/TLS certificate inventory and compliance)
- Master Inventory Reconciliation: Azure Resource Manager (monthly inventory reviews and change tracking)

=========================================================================================
2 (a). Required Microsoft Graph API Permissions
=========================================================================================
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

All of the above must be added as **Application** permissions (not Delegated), and you must grant admin consent in the Azure portal after adding them. Then, generate a new access token for the app.

=========================================================================================
2 (b). Required Azure Resource Manager (ARM) Permissions
=========================================================================================
For the script to retrieve Azure resource configurations, your Azure AD application (service principal) must be assigned the following Azure RBAC role at the **subscription** or **resource group** level:

- **Reader** (built-in role)

This role grants read-only access to all resources, which is sufficient for all the ARM API requests made by the script. The script does not require any write or contributor permissions.

The following resource types are accessed:
- Microsoft.Network/networkSecurityGroups/read (for NSG SMTP block evidence)
- Microsoft.Network/azureFirewalls/read (for Azure Firewall SMTP block evidence)
- Microsoft.Network/bastionHosts/read (for Bastion Host configuration and SSH timeout evidence)
- Microsoft.OperationalInsights/workspaces/providers/Microsoft.SecurityInsights/incidents/read (for Sentinel incident evidence)
- Microsoft.Authorization/policyAssignments/read
- Microsoft.Security/pricings/read
- Microsoft.OperationalInsights/workspaces/read
- Microsoft.OperationalInsights/workspaces/providers/Microsoft.Authorization/roleAssignments/read
- Microsoft.SecurityInsights/alertRules/read
- Microsoft.Insights/diagnosticSettings/read
- Microsoft.CertificateManager/certificateManagers/read and /certificates/read
- Microsoft.KeyVault/vaults/read and /certificates/read

**How to assign:**
- In the Azure Portal: Go to Subscriptions (or Resource Groups) → [Your Subscription/Resource Group] → Access control (IAM) → Add role assignment → Select 'Reader' → Assign to your app registration (service principal).
- Or use the Azure CLI: `az role assignment create --assignee <appId> --role Reader --scope /subscriptions/<subscriptionId>`

No additional custom permissions are required for read-only evidence gathering.

=========================================================================================
3. API Endpoints Used
=========================================================================================
The script uses the following API endpoints:

Microsoft Graph API Endpoints:
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
- https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles
- https://graph.microsoft.com/v1.0/security/alerts
- /identityGovernance/lifecycleWorkflows/workflows
- /identityGovernance/accessReviews/definitions
- /auditLogs/directoryAudits (with various filters for revocation events)
- /auditLogs/directoryAudits (with various filters for credential distribution, access reviews, etc.)
- /groups (for group membership and access control)
- /directoryRoles (for administrative role assignments)

Azure Resource Manager (ARM) API Endpoints:
- /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Network/bastionHosts?api-version=2023-05-01
- /subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyAssignments
- /subscriptions/{subscriptionId}/providers/Microsoft.Security/pricings?api-version=2022-03-01-preview
- /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}?api-version=2022-10-01
- /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01
- /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/alertRules?api-version=2022-12-01-preview
- /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01-preview
- /subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.OperationalInsights/workspaces/{workspaceName}/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2022-12-01-preview
- /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2022-05-01
- /subscriptions/{subscriptionId}/providers/Microsoft.Network/azureFirewalls?api-version=2022-05-01
- {resourceId}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview
- /subscriptions/{subscriptionId}/providers/Microsoft.CertificateManager/certificateManagers?api-version=2022-01-01
- /subscriptions/{subscriptionId}/providers/Microsoft.CertificateManager/certificates?api-version=2022-01-01
- /subscriptions/{subscriptionId}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01
- /subscriptions/{subscriptionId}/providers/Microsoft.Network/dnsZones?api-version=2018-05-01
- /subscriptions/{subscriptionId}/providers/Microsoft.Network/applicationGateways?api-version=2022-09-01
- /subscriptions/{subscriptionId}/providers/Microsoft.Cdn/profiles?api-version=2021-06-01
- /subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2022-09-01
- /subscriptions/{subscriptionId}/providers/Microsoft.RecoveryServices/vaults?api-version=2022-08-01
- /subscriptions/{subscriptionId}/resources?api-version=2021-04-01
- /subscriptions/{subscriptionId}/providers/Microsoft.Resources/deployments?api-version=2021-04-01
- /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01
- /subscriptions/{subscriptionId}/providers/Microsoft.Security/alerts?api-version=2020-01-01
- /subscriptions/{subscriptionId}/providers/microsoft.insights/eventTypes/management/values?api-version=2015-04-01