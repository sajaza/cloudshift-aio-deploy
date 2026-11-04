"""Microsoft Graph application permissions the cloudshift inventory app needs. All read-only.

Shared by register-entra.py (new registrations) and deploy-azure.py (existing ones).
"""
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
READ_PERMISSIONS = (
    "User.Read.All",                            # users, standards
    "Device.Read.All",                          # Entra devices
    "LicenseAssignment.Read.All",               # licences
    "Policy.Read.All",                          # Conditional Access
    "DeviceManagementManagedDevices.Read.All",  # Intune devices
    "SecurityIncident.Read.All",                # Defender incidents
    "DeviceManagementApps.Read.All",            # Intune app catalog
    "Organization.Read.All",                    # Microsoft 365 organisation
    "Domain.Read.All",                          # Microsoft 365 domains
    "ServiceHealth.Read.All",                   # Microsoft 365 service health
    "Group.Read.All",                           # Groups, Teams
    "AuditLog.Read.All",                        # Sign-ins, Audit log, MFA, Inactive users
    "IdentityRiskyUser.Read.All",               # Risky users
    "IdentityRiskEvent.Read.All",               # Risk detections
    "RoleManagement.Read.Directory",            # Roles
    "Application.Read.All",                     # Applications, Consented apps
    "SecurityEvents.Read.All",                  # Secure Score
    "SecurityAlert.Read.All",                   # Defender alerts
    "ConsentRequest.Read.All",                  # App consent requests
    "DeviceManagementConfiguration.Read.All",   # Intune configuration/compliance policies, scripts
    "DeviceManagementServiceConfig.Read.All",   # Autopilot
    "Sites.Read.All",                           # SharePoint sites
)
