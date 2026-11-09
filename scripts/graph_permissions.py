"""Application permissions the cloudshift inventory app needs. All read-only.

READ_PERMISSIONS are Microsoft Graph application roles. EXCHANGE_READ_PERMISSIONS are application roles
on a different resource API (Office 365 Exchange Online) and are kept in their own constant, so the
Graph list stays Graph-only. Shared by register-entra.py (new registrations), deploy-azure.py and
grant-permissions.py (existing ones).
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
    "Reports.Read.All",                         # Usage reports: OneDrive, Mailbox Activity/Statistics, Teams
                                                # Activity, Group Usage, Graph/Office Reports, Copilot reports
    # Wave 4 blades
    "CrossTenantInformation.ReadBasic.All",     # Partner Relationships (organisation names)
    "ConfigurationMonitoring.Read.All",         # Standards & Drift (Microsoft configuration drift)
    "SensitivityLabel.Read",                    # Sensitivity Labels
    "AppCatalog.Read.All",                      # Agent365 Packages (org Teams app catalogue)
    "BitlockerKey.ReadBasic.All",               # BitLocker Key Search (key IDs only, never the key)
    "TeamsTelephoneNumber.Read.All",            # Business Voice (phone numbers)
    # Wave 3 blades
    "ExchangeMessageTrace.Read.All",            # Message Trace (Graph v1.0; delivery metadata, no subjects shown)
    "DeviceManagementScripts.Read.All",         # Scripts (Graph beta Preview; names/settings, never script content)
    "CloudApp-Discovery.Read.All",              # Shadow AI Discovery (Graph beta Preview; Defender for Cloud Apps)
)

# Opt-in only: ThreatHunting.Read.All lets the app run any advanced hunting query over a tenant's Defender
# XDR data, although AIO runs only two fixed vulnerability queries (Vulnerabilities, Vulnerability Report).
# It is never in the registration's requested permissions (the registration is multitenant, and an
# admin-consent link consents everything requested), only consented directly per tenant: AIO's own tenant
# with grant-permissions.py --enable-defender-hunting (--disable-defender-hunting removes it), a customer
# tenant by its administrator with the Graph PowerShell that grant-permissions.py prints.
HUNTING_PERMISSIONS = (
    "ThreatHunting.Read.All",
)
# Microsoft Graph's app role ID for ThreatHunting.Read.All (the same in every tenant); used only in the
# printed customer-tenant steps. The home tenant resolves role IDs from Graph itself.
HUNTING_ROLE_ID = "dd98c7f5-2d42-42d3-a0e4-633161547251"

# Office 365 Exchange Online (the resource for https://outlook.office365.com). Exchange.ManageAsApp only
# lets the app call Exchange Online app-only; what it can do there is decided solely by the Exchange role
# the tenant gives it. AIO asks for View-Only Organization Management (read-only), never a write role.
EXCHANGE_APP_ID = "00000002-0000-0ff1-ce00-000000000000"
EXCHANGE_READ_PERMISSIONS = (
    "Exchange.ManageAsApp",                     # Exchange Online read-only blades (fixed Get-* cmdlets)
)
EXCHANGE_ROLE_GROUP = "View-Only Organization Management"
# Microsoft's message trace service; Graph message trace needs its service principal in the tenant.
MESSAGE_TRACE_APP_ID = "8bd644d1-64a1-4d4b-ae52-2e0cbf64e373"
