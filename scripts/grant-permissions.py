#!/usr/bin/env python3
"""Make AIO's read-only Microsoft Graph and Exchange Online access live in your tenant, then prove it
(macOS, Linux or Windows).

Adds any missing read permission to cloudshift inventory (Microsoft Graph, plus Exchange.ManageAsApp on
Office 365 Exchange Online), admin-consents exactly those permissions, calls Microsoft Graph once per area
as AIO does, runs one harmless read-only Exchange cmdlet (Get-OrganizationConfig), then restarts the
hosted app so it uses the new access. Exchange also needs a read-only Exchange role
(View-Only Organization Management), which only Exchange Online PowerShell can assign: when it is
missing, the script prints the exact commands instead. Never prints credential values. Python standard
library only.
Run --check-only to only test, without changing anything.
Defender advanced hunting (ThreatHunting.Read.All, used by the two Vulnerabilities blades) is opt-in:
add --enable-defender-hunting to consent it, or --disable-defender-hunting to remove it.
An install using workload identity federation whose inventory client secret was removed cannot be tested
from here (only the Container App's managed identity can sign in as cloudshift inventory); the script
then requests, consents and restarts, and the areas are checked in AIO itself.
"""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

spec = importlib.util.spec_from_file_location("deployment", Path(__file__).with_name("deploy-azure.py"))
deployment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployment)
SetupError, cli, identifier = deployment.SetupError, deployment.cli, deployment.identifier

# One small request per AIO area, mirroring src/lib/microsoft/graph.ts.
CHECKS = (
    ("Users", "User.Read.All", "/v1.0/users?$select=id&$top=1"),
    ("Entra devices", "Device.Read.All", "/v1.0/devices?$select=id&$top=1"),
    ("Licences", "LicenseAssignment.Read.All", "/v1.0/subscribedSkus?$select=id"),
    ("Conditional Access", "Policy.Read.All", "/v1.0/identity/conditionalAccess/policies?$select=id"),
    ("Intune devices", "DeviceManagementManagedDevices.Read.All",
     "/v1.0/deviceManagement/managedDevices?$select=id&$top=1"),
    ("Defender incidents", "SecurityIncident.Read.All", "/v1.0/security/incidents?$top=1"),
    ("Intune apps", "DeviceManagementApps.Read.All", "/v1.0/deviceAppManagement/mobileApps?$select=id&$top=1"),
    ("Organisation", "Organization.Read.All", "/v1.0/organization?$select=id"),
    ("Domains", "Domain.Read.All", "/v1.0/domains?$select=id"),
    ("Service health", "ServiceHealth.Read.All", "/v1.0/admin/serviceAnnouncement/healthOverviews?$select=id"),
    ("Groups", "Group.Read.All", "/v1.0/groups?$select=id&$top=1"),
    # Directory audits work on every tenant, so a free tenant passes; sign-in logs also need Entra ID P1.
    ("Audit log", "AuditLog.Read.All", "/v1.0/auditLogs/directoryAudits?$top=1"),
    ("Risky users", "IdentityRiskyUser.Read.All", "/v1.0/identityProtection/riskyUsers?$top=1"),
    ("Risk detections", "IdentityRiskEvent.Read.All", "/v1.0/identityProtection/riskDetections?$top=1"),
    ("Roles", "RoleManagement.Read.Directory", "/v1.0/directoryRoles"),
    ("Applications", "Application.Read.All", "/v1.0/applications?$select=id&$top=1"),
    ("Secure Score", "SecurityEvents.Read.All", "/v1.0/security/secureScores?$top=1"),
    ("Defender alerts", "SecurityAlert.Read.All", "/v1.0/security/alerts_v2?$top=1"),
    ("App consent requests", "ConsentRequest.Read.All",
     "/v1.0/identityGovernance/appConsent/appConsentRequests?$top=1"),
    ("Intune policies", "DeviceManagementConfiguration.Read.All",
     "/v1.0/deviceManagement/deviceConfigurations?$select=id&$top=1"),
    ("Autopilot", "DeviceManagementServiceConfig.Read.All",
     "/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$top=1"),
    ("SharePoint sites", "Sites.Read.All", "/v1.0/sites/root?$select=id"),
    # Answers 302 to a short-lived CSV download; the redirect is not followed (see graph_status).
    ("Usage reports", "Reports.Read.All", "/v1.0/reports/getOffice365ActivationsUserCounts"),
    ("Partner names", "CrossTenantInformation.ReadBasic.All",
     "/v1.0/tenantRelationships/findTenantInformationByDomainName(domainName='microsoft.com')"),
    ("Configuration drift", "ConfigurationMonitoring.Read.All",
     "/v1.0/admin/configurationManagement/configurationMonitors"),
    # POST is the documented query verb; the body is the fixed HUNTING_CHECK_BODY (see graph_status).
    ("Advanced hunting", "ThreatHunting.Read.All", "/v1.0/security/runHuntingQuery"),
    ("Sensitivity labels", "SensitivityLabel.Read", "/v1.0/security/dataSecurityAndGovernance/sensitivityLabels"),
    ("Teams app catalogue", "AppCatalog.Read.All",
     "/v1.0/appCatalogs/teamsApps?$filter=distributionMethod%20eq%20'organization'"),
    # Key IDs and dates only: the recovery key is returned only for $select=key, which is never sent.
    ("BitLocker key IDs", "BitlockerKey.ReadBasic.All", "/v1.0/informationProtection/bitlocker/recoveryKeys"),
    ("Teams phone numbers", "TeamsTelephoneNumber.Read.All",
     "/v1.0/admin/teams/telephoneNumberManagement/numberAssignments?$top=1"),
    # Delivery metadata of the last 48 hours; needs Microsoft's message trace service principal (created below).
    ("Message trace", "ExchangeMessageTrace.Read.All", "/v1.0/admin/exchange/tracing/messageTraces?$top=1"),
    # Preview blades: only a Graph beta API exists (see src/lib/modules/graph-beta.ts). Never scriptContent.
    ("Intune scripts (Preview)", "DeviceManagementScripts.Read.All",
     "/beta/deviceManagement/deviceManagementScripts?$select=id"),
    ("Cloud app discovery (Preview)", "CloudApp-Discovery.Read.All",
     "/beta/security/dataDiscovery/cloudAppDiscovery/uploadedStreams"),
)
# Graph checks that call beta, because the AIO area itself is a Preview blade on a beta-only API.
BETA_CHECKS = {"DeviceManagementScripts.Read.All", "CloudApp-Discovery.Read.All"}
# Exchange Online live check: one fixed, harmless read-only cmdlet, never built from input.
EXCHANGE_SCOPE = "https://outlook.office365.com/.default"
EXCHANGE_CHECK_CMDLET = "Get-OrganizationConfig"
EXCHANGE_PERMISSION = "Exchange.ManageAsApp"
EXCHANGE_SYSTEM_MAILBOX = "SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}"
HUNTING_PATH = "/v1.0/security/runHuntingQuery"
# Fixed read-only KQL used only to prove ThreatHunting.Read.All works; never built from input.
HUNTING_CHECK_BODY = {"Query": "DeviceInfo | take 1"}
# Areas that also need a product licence in the tenant, not just consent.
LICENSED = {"DeviceManagementManagedDevices.Read.All": "Intune", "DeviceManagementApps.Read.All": "Intune",
            "DeviceManagementConfiguration.Read.All": "Intune", "DeviceManagementServiceConfig.Read.All": "Intune",
            "SecurityIncident.Read.All": "Microsoft Defender XDR", "SecurityAlert.Read.All": "Microsoft Defender XDR",
            "IdentityRiskyUser.Read.All": "Microsoft Entra ID P2",
            "IdentityRiskEvent.Read.All": "Microsoft Entra ID P2", "Sites.Read.All": "SharePoint Online",
            "ThreatHunting.Read.All": "Microsoft Defender for Endpoint",
            "SensitivityLabel.Read": "Microsoft Purview Information Protection",
            "DeviceManagementScripts.Read.All": "Intune",
            "CloudApp-Discovery.Read.All": "Microsoft Defender for Cloud Apps",
            "ExchangeMessageTrace.Read.All": "Exchange Online"}
# Permissions AIO never requests by default; the check reports them as off until enabled.
OPT_IN = {"ThreatHunting.Read.All": "Vulnerabilities and Vulnerability Report need it; it allows any Defender "
          "advanced hunting query, so add it per tenant with --enable-defender-hunting."}
# Areas whose check passes on any tenant but where part of the AIO area needs a licence.
PARTLY_LICENSED = {"AuditLog.Read.All": "sign-in logs (Sign-ins, MFA, Inactive users) also need Microsoft Entra ID P1",
                   "Reports.Read.All": "Copilot usage reports also need Microsoft 365 Copilot licences",
                   "TeamsTelephoneNumber.Read.All": "phone numbers exist only with Teams Phone"}
WAIT_SECONDS = 300  # new consent usually reaches app tokens within a few minutes


def post_form(url, fields):
    request = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode(), method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        try:
            codes = json.load(error).get("error_codes", [])
        except (ValueError, AttributeError):
            codes = []
        # AADSTS codes are safe to show and say what is wrong (7000215 = wrong secret, 7000222 = expired).
        detail = " (AADSTS" + str(codes[0]) + ")" if codes else ""
        raise SetupError("Microsoft refused the cloudshift inventory sign-in" + detail +
                         ". Check GRAPH_CLIENT_ID and GRAPH_CLIENT_SECRET in your configuration file.") from None
    except (urllib.error.URLError, OSError, ValueError):
        raise SetupError("Could not reach Microsoft sign-in; check your internet connection.") from None


def app_token(settings, scope="https://graph.microsoft.com/.default"):
    """Client-credentials token for cloudshift inventory, exactly as the hosted app gets one."""
    result = post_form(f"https://login.microsoftonline.com/{settings['ENTRA_TENANT_ID']}/oauth2/v2.0/token", {
        "client_id": settings["GRAPH_CLIENT_ID"], "client_secret": settings["GRAPH_CLIENT_SECRET"],
        "scope": scope, "grant_type": "client_credentials"})
    token = result.get("access_token")
    if not isinstance(token, str):
        raise SetupError("Microsoft sign-in returned no token for cloudshift inventory.")
    return token


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: a usage report's 302 points at a download host that must not get the token."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Opener without automatic redirects; a 3xx surfaces as HTTPError and is never followed.
OPENER = urllib.request.build_opener(NoRedirect)


def graph_status(path, token):
    """(HTTP status, Graph error code) for one request. Response bodies are never printed.

    Every check is a GET except advanced hunting, whose documented read verb is POST with a fixed query.

    A 302/303 from Graph means it authorised the report and issued a download link, so it counts as 200;
    the link (on a reports host) is not fetched.
    """
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    data = None
    if path == HUNTING_PATH:
        headers["Content-Type"] = "application/json"
        data = json.dumps(HUNTING_CHECK_BODY).encode()
    request = urllib.request.Request("https://graph.microsoft.com" + path, data=data, headers=headers,
                                     method="POST" if data else "GET")
    try:
        with OPENER.open(request, timeout=30) as response:
            return response.status, ""
    except urllib.error.HTTPError as error:
        if error.code in (302, 303):
            error.close()
            return 200, ""
        try:
            code = json.load(error).get("error", {}).get("code", "")
        except (ValueError, AttributeError):
            code = ""
        return error.code, code if isinstance(code, str) and code.replace("_", "").isalnum() else ""
    except (urllib.error.URLError, OSError):
        return 0, "NetworkError"


def token_roles(token):
    """Application roles in an access token (read locally from its payload; the token is never printed)."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        roles = claims.get("roles", [])
        return [r for r in roles if isinstance(r, str)] if isinstance(roles, list) else []
    except (IndexError, ValueError, AttributeError, TypeError):
        return []


def exchange_status(tenant_id, token):
    """HTTP status of one fixed Get-OrganizationConfig call through Exchange Online's admin endpoint (the one
    the ExchangeOnlineManagement module uses; not documented as a public API). Bodies are never printed and
    redirects are never followed."""
    tenant = identifier(tenant_id)
    body = json.dumps({"CmdletInput": {"CmdletName": EXCHANGE_CHECK_CMDLET, "Parameters": {}}}).encode()
    request = urllib.request.Request(
        f"https://outlook.office365.com/adminapi/beta/{tenant}/InvokeCommand", data=body, method="POST",
        headers={"Authorization": "Bearer " + token, "Accept": "application/json",
                 "Content-Type": "application/json", "X-ResponseFormat": "json",
                 "X-AnchorMailbox": f"APP:{EXCHANGE_SYSTEM_MAILBOX}@{tenant}",
                 "X-CmdletName": EXCHANGE_CHECK_CMDLET})
    try:
        with OPENER.open(request, timeout=60) as response:
            return response.status
    except urllib.error.HTTPError as error:
        error.close()
        return error.code
    except (urllib.error.URLError, OSError):
        return 0


def exchange_check(settings):
    """("live" | "permission" | "role" | "failed", HTTP status) for Exchange Online read access.

    "permission": the app's Exchange token carries no Exchange.ManageAsApp (not consented yet).
    "role": the permission is there but Exchange refuses the read-only cmdlet (no Exchange role)."""
    try:
        token = app_token(settings, EXCHANGE_SCOPE)
    except SetupError:
        return "permission", 0
    if EXCHANGE_PERMISSION not in token_roles(token):
        return "permission", 0
    status = exchange_status(settings["ENTRA_TENANT_ID"], token)
    if status == 200:
        return "live", status
    if status == 401:
        return "permission", status
    if status in (400, 403, 404):
        return "role", status
    return "failed", status


def explain_exchange(state, status, steps):
    if state == "live":
        return ["live (" + EXCHANGE_CHECK_CMDLET + " answered; role " + deployment.EXCHANGE_ROLE_GROUP + ")"]
    if state == "permission":
        return [f"permission missing: {EXCHANGE_PERMISSION} (Office 365 Exchange Online) is not consented "
                "yet. Rerun this script as an admin; consent can take a few minutes."]
    if state == "role":
        return [f"role missing ({status}): the app has {EXCHANGE_PERMISSION} but no Exchange role. An Exchange "
                "Administrator runs once in Exchange Online PowerShell:", *("      " + line for line in steps)]
    return [f"failed ({status or 'network'}). Try again shortly."]


def run_checks(settings, wait):
    """Test every area; while some are denied, retry with fresh tokens for up to `wait` seconds."""
    deadline = time.monotonic() + wait
    while True:
        token = app_token(settings)
        results = [(label, permission, *graph_status(path, token)) for label, permission, path in CHECKS]
        # Opt-in areas are expected to be denied until enabled; don't wait on them.
        denied = [r for r in results if r[2] in (401, 403) and r[1] not in OPT_IN]
        if not denied or time.monotonic() >= deadline:
            return results
        print(f"  {len(denied)} area(s) not live yet; Microsoft can take a few minutes. Retrying in 30s…",
              flush=True)
        time.sleep(30)


def explain(permission, status, code):
    if status in (401, 403) and permission in OPT_IN:
        return f"off (opt-in). {OPT_IN[permission]}"
    if status == 200:
        return "live; " + PARTLY_LICENSED[permission] if permission in PARTLY_LICENSED else "live"
    if status in (401, 403) and permission in LICENSED:
        return (f"denied ({status}). Consent can take a few minutes; if it stays denied the tenant may not "
                f"have {LICENSED[permission]}, so AIO shows this area as unavailable.")
    if status in (401, 403):
        return f"denied ({status}). {permission} is not consented yet; rerun this script as an admin."
    if status in (400, 404) and permission in LICENSED:
        return f"not available ({status} {code}). The tenant probably has no {LICENSED[permission]} licence."
    return f"failed ({status} {code or 'no code'}). Try again shortly."


def restart_app(group, name):
    """Restart the hosted app so it drops cached Graph tokens. Returns False if it is not deployed."""
    app = deployment.app_details(group, name)
    revision = (app or {}).get("properties", {}).get("latestRevisionName")
    if not revision:
        return False
    cli(["containerapp", "revision", "restart", "--resource-group", group, "--name", name,
         "--revision", revision])
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=deployment.DEFAULT_ENV, help="Live configuration file")
    parser.add_argument("--resource-group", default="cloudshift-rg")
    parser.add_argument("--name", default="cloudshift", help="Container App name")
    parser.add_argument("--check-only", action="store_true", help="Only test access; change nothing")
    hunting = parser.add_mutually_exclusive_group()
    hunting.add_argument("--enable-defender-hunting", action="store_true",
                         help="Opt in: also request and consent ThreatHunting.Read.All (Vulnerabilities blades)")
    hunting.add_argument("--disable-defender-hunting", action="store_true",
                         help="Remove ThreatHunting.Read.All consent and request from cloudshift inventory")
    args = parser.parse_args()
    if args.check_only and (args.enable_defender_hunting or args.disable_defender_hunting):
        raise SetupError("--check-only changes nothing; drop it to enable or disable Defender hunting.")
    settings = deployment.load_settings(args.env_file)
    app_id = settings["GRAPH_CLIENT_ID"]
    names = deployment.READ_PERMISSIONS
    # A federated install that ran --remove-secrets has no local inventory secret: only the Container
    # App's managed identity can get its token, so the live check runs in AIO, not here.
    testable = bool(settings.get("GRAPH_CLIENT_SECRET"))
    if not testable and args.check_only:
        raise SetupError("This install uses workload identity federation and the settings file holds no "
                         "inventory client secret, so the check cannot run from here. Sign in to AIO and "
                         "open each area instead; nothing was changed.")
    progress = deployment.Progress((2 if args.check_only else 6) if testable else 4)
    changed = False
    principal = None
    if not args.check_only:
        if not shutil.which("az"):
            raise SetupError("Install Microsoft's Azure CLI, then sign in with az login --tenant TENANT_ID.")
        progress.step("Checking your Azure sign-in")
        account = cli(["account", "show"])
        if identifier(account.get("tenantId")) != settings["ENTRA_TENANT_ID"]:
            raise SetupError("Azure CLI is signed in to a different tenant than AIO. "
                             "Run az login --tenant " + settings["ENTRA_TENANT_ID"])
        print("Signed in as " + str(account.get("user", {}).get("name", "unknown")))
        progress.step(f"Requesting the {len(names) + len(deployment.EXCHANGE_READ_PERMISSIONS)} read-only "
                      "permissions on cloudshift inventory")
        added = deployment.ensure_read_permissions(app_id) + deployment.ensure_exchange_permissions(app_id)
        # Never leave an opt-in permission requested: the multitenant registration's admin-consent link would
        # then grant it in every customer tenant that consents. Existing consent here is not touched.
        unrequested = deployment.remove_requested(app_id, deployment.HUNTING_PERMISSIONS)
        if unrequested:
            print("  no longer requested by default (opt-in): " + ", ".join(unrequested))
        print("  added: " + ", ".join(added) if added else "  all already requested")
        progress.step("Granting admin consent for exactly those permissions")
        try:
            granted = deployment.grant_read_permissions(app_id) + deployment.grant_exchange_permissions(app_id)
            principal = deployment.service_principal(app_id)
        except SetupError:
            raise SetupError("Admin consent failed. Sign in as a Global Administrator or Privileged Role "
                             "Administrator (az login --tenant " + settings["ENTRA_TENANT_ID"] + ") and rerun, "
                             "or grant it in Entra → App registrations → cloudshift inventory → API "
                             "permissions → Grant admin consent.") from None
        print("  granted: " + ", ".join(granted) if granted else "  already granted")
        if args.enable_defender_hunting:
            # Consented in this tenant only (an appRoleAssignment needs no requiredResourceAccess entry), so a
            # customer tenant's admin-consent link never includes it.
            hunting_granted = deployment.grant_app_roles(app_id, deployment.HUNTING_PERMISSIONS)
            print("  Defender hunting (opt-in, this tenant only): " + ("enabled" if hunting_granted
                                                                     else "already enabled"))
            granted = granted + hunting_granted
        elif args.disable_defender_hunting:
            revoked = deployment.revoke_app_roles(app_id, deployment.HUNTING_PERMISSIONS)
            print("  Defender hunting: " + ("consent removed" if revoked else "was not consented")
                  + "; Vulnerabilities blades now show a permission message")
            granted = granted + revoked
        try:
            # Documented prerequisite of Graph message trace; it grants nothing to cloudshift.
            deployment.ensure_message_trace_principal()
        except SetupError:
            print("  could not add Microsoft's message trace service principal (needs an Application "
                  "Administrator); Message Trace stays unavailable until it exists")
        changed = bool(added or granted)
    results = []
    exchange = None
    if testable:
        progress.step("Getting an app sign-in for cloudshift inventory")
        app_token(settings)
        print("  signed in")
        progress.step("Testing each AIO area against Microsoft Graph",
                      "under 1 min; up to 5 min after new consent")
        # Only wait for propagation when this run changed access; otherwise a denial is the real answer.
        results = run_checks(settings, WAIT_SECONDS if changed else 0)
        print("  checking Exchange Online with " + EXCHANGE_CHECK_CMDLET + " (read-only)", flush=True)
        exchange = exchange_check(settings)
    elif changed:
        # No local check to wait on: give new consent time to reach the app's next token before restarting.
        print("  waiting 2 minutes for the new consent to apply before the restart", flush=True)
        time.sleep(120)
    if not args.check_only:
        # After the checks, so the app's next Graph token is issued once the new access is in effect.
        progress.step("Restarting AIO so it drops its old Microsoft sign-in", "under 1 min")
        try:
            restarted = restart_app(args.resource_group, args.name)
        except SetupError:
            restarted = False
        print("  restarted" if restarted else f"  no running app '{args.name}' in {args.resource_group}; "
              "restart it from Container App → Revisions → Restart if it runs elsewhere")
    progress.finish()
    print()
    if not testable:
        print("Skipped the live check: this install uses workload identity federation and the settings file")
        print("holds no inventory client secret (the app signs in with its managed identity). Sign in to AIO")
        print("and open each area to confirm; an area missing a licence shows as unavailable there.")
        print("Exchange Online also needs the read-only role " + deployment.EXCHANGE_ROLE_GROUP + "; if the")
        print("Exchange areas say 'Exchange role required', an Exchange Administrator runs once in Exchange Online")
        print("PowerShell:")
        for line in deployment.exchange_role_steps(app_id, principal):
            print("      " + line)
        return
    width = max(len(label) for label, *_ in results)
    for label, permission, status, code in results:
        print(f"  {'✓' if status == 200 else '✗'} {label.ljust(width)}  {explain(permission, status, code)}")
    steps = deployment.exchange_role_steps(app_id, principal)
    state, status = exchange
    lines = explain_exchange(state, status, steps)
    print(f"  {'✓' if state == 'live' else '✗'} {'Exchange Online'.ljust(width)}  {lines[0]}")
    for line in lines[1:]:
        print(line)
    live = sum(status == 200 for *_, status, _ in results) + (state == "live")
    total = len(results) + 1
    print()
    print(f"{live} of {total} areas are live.")
    print("Customer tenants: a Global Administrator there opens https://login.microsoftonline.com/<tenant-id>/"
          f"adminconsent?client_id={app_id}")
    print("  This consents every permission cloudshift inventory requests (Microsoft Graph and Exchange, all")
    print("  read-only), not only Exchange. Then run the same Exchange PowerShell there with that tenant's")
    print("  object ID of cloudshift inventory.")
    print("  Defender hunting is never part of that consent. To opt a customer tenant in, its administrator")
    print("  runs (Microsoft Graph PowerShell, in that tenant):")
    for line in deployment.opt_in_role_steps(app_id, deployment.HUNTING_ROLE_ID):
        print("      " + line)
    if live < total:
        print("Rerun later with --check-only to test again without changing anything.")
    sys.exit(0 if live == total else 2)


if __name__ == "__main__":
    try:
        main()
    except (SetupError, OSError, KeyError, TypeError, ValueError):
        error = sys.exc_info()[1]
        print("Permissions stopped: " + (str(error) if isinstance(error, SetupError) else
              "Local failure; configuration values and response details were not logged."), file=sys.stderr)
        sys.exit(1)
