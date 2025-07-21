#!/usr/bin/env python3
"""
Security Policy Printer v3 - Main Entry Point

This script orchestrates the execution of all security policy checks and outputs the results.
"""

import sys
from helpers import Config, APIClient, Formatter, setup_output
from security_functions import SecurityFunctions
from token_manager import TokenManager

def main():
    # Load configuration
    config = Config.from_file()

    # Initialize token manager and get tokens
    token_manager = TokenManager(config)
    tokens = token_manager.get_tokens()
    
    if not tokens:
        print("\nFailed to obtain access tokens. Check your Azure credentials in config.json")
        sys.exit(1)

    # Setup output redirection
    out_file = setup_output(config)

    try:
        # Initialize components
        api_client = APIClient(tokens, config)
        formatter = Formatter()
        sf = SecurityFunctions(api_client, formatter, config)

        # Print header
        formatter.print_header(
            "Microsoft Entra ID Security Policies Configuration Retriever",
            "Comprehensive security policy analysis and reporting tool"
        )

        # Run security checks
        print("\n" + "=" * 80)
        print("INFRASTRUCTURE AND COMPLIANCE")
        print("=" * 80)
        # sf.check_smart_lockout_settings()
        # sf.check_password_protection_policy()
        # sf.check_conditional_access_policies()
        # sf.check_intune_machine_inactivity_limit()
        # sf.check_available_permissions()
        # sf.check_intune_compliance_policy()
        sf.check_azure_functions_multi_az()
        
        print("\n" + "=" * 80)
        print("SENTINEL AND MONITORING")
        print("=" * 80)
        # sf.check_sentinel_error_analytic_rules()
        # sf.check_sentinel_defender_connector_status()
        sf.check_sentinel_defender_endpoint_connector_status()
        sf.check_sentinel_connected_workspaces()
        # sf.check_sentinel_incident_summary()
        # sf.check_sentinel_log_deletion_alert_rules()
        # sf.check_recent_sentinel_error_logs(hours_back=24)
        # sf.check_sentinel_privileged_command_auditing()
        # sf.check_sentinel_comprehensive_audit_records()
        
        print("\n" + "=" * 80)
        print("DEFENDER AND SECURITY")
        print("=" * 80)
        # sf.check_defender_for_cloud_failed_checks()
        sf.check_defender_fim_configuration()
        # sf.check_defender_app_control_status()
        # sf.check_defender_endpoint_malware_protection()
        
        # print("\n" + "=" * 80)
        # print("NETWORK SECURITY")
        # print("=" * 80)
        # sf.check_waf_deployment_and_policy_status()
        # sf.check_dnssec_status()
        # sf.check_nsg_smtp_block_status()
        # sf.check_firewall_smtp_block_status()
        # sf.check_bastion_ssh_timeout_status()
        
        # print("\n" + "=" * 80)
        # print("INFRASTRUCTURE AND COMPLIANCE")
        # print("=" * 80)
        # sf.check_admin_group_membership()
        sf.check_blob_storage_audit_retention()
        sf.check_fips_validated_encryption()
        # sf.check_recovery_services_backup_policies()
        # sf.check_missing_assettag_resources()
        # sf.check_log_analytics_immutability()
        # sf.check_pim_role_assignment_policies()
        # sf.check_intune_device_compliance_details()
        # sf.check_certificate_compliance_evidence()
        # sf.check_master_inventory_reconciliation()
        # sf.check_infrastructure_vulnerability_scans()
        # sf.check_insider_threat_escalation()
        
        # print("\n" + "=" * 80)
        # print("RISK-BASED SECURITY")
        # print("=" * 80)
        # sf.check_user_risk_policy()
        # sf.check_identity_protection_risk_detections(10)
        # sf.check_sign_in_risk_policy(10)
        
        print("\n" + "=" * 80)
        print("INFRASTRUCTURE AND MONITORING")
        print("=" * 80)
        # sf.check_bastion_host_settings()
        # sf.check_encryption_policy_and_defender_status()
        # sf.check_log_analytics_retention_settings()
        # sf.check_workspace_rbac()
        # sf.check_credential_distribution_audit_events(10)
        # sf.check_cis_l1_initiative_assignment()
        # sf.check_waf_diagnostic_settings()
        sf.check_recent_fim_alerts(10)
        # sf.check_arm_template_configuration_orchestration()
        sf.check_recent_sentinel_security_alerts(24)
        sf.check_recent_security_incidents()
        
        # print("\n" + "=" * 80)
        # print("ADVANCED SECURITY CONTROLS")
        # print("=" * 80)
        # sf.check_intrusion_detection_systems()
        # sf.check_logical_access_review()
        # sf.check_logical_access_revocation()
        # sf.check_screen_lock_obfuscation_settings()

        print("\n" + "=" * 80)
        print("SECURITY POLICY CHECK COMPLETE")
        print("=" * 80)
        print(f"Results saved to: {config.output_file}")

    except KeyboardInterrupt:
        print("\n\nScript interrupted by user.")
    except Exception as e:
        print(f"\n\nAn error occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Restore stdout
        if 'out_file' in locals():
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__
            out_file.close()

if __name__ == "__main__":
    main() 