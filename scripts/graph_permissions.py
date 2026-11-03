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
)
