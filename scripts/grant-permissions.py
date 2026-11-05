#!/usr/bin/env python3
"""Make AIO's read-only Microsoft Graph access live in your tenant, then prove it (macOS, Linux or Windows).

Adds any missing read permission to cloudshift inventory, admin-consents exactly those permissions,
calls Microsoft Graph once per area as AIO does, then restarts the hosted app so it uses the new
access. Never prints credential values. Python standard library only.
Run --check-only to only test, without changing anything.
"""
import argparse
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
)
# Areas that also need a product licence in the tenant, not just consent.
LICENSED = {"DeviceManagementManagedDevices.Read.All": "Intune", "DeviceManagementApps.Read.All": "Intune",
            "DeviceManagementConfiguration.Read.All": "Intune", "DeviceManagementServiceConfig.Read.All": "Intune",
            "SecurityIncident.Read.All": "Microsoft Defender XDR", "SecurityAlert.Read.All": "Microsoft Defender XDR",
            "IdentityRiskyUser.Read.All": "Microsoft Entra ID P2",
            "IdentityRiskEvent.Read.All": "Microsoft Entra ID P2", "Sites.Read.All": "SharePoint Online"}
# Areas whose check passes on any tenant but where part of the AIO area needs a licence.
PARTLY_LICENSED = {"AuditLog.Read.All": "sign-in logs (Sign-ins, MFA, Inactive users) also need Microsoft Entra ID P1",
                   "Reports.Read.All": "Copilot usage reports also need Microsoft 365 Copilot licences"}
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


def app_token(settings):
    """Client-credentials token for cloudshift inventory, exactly as the hosted app gets one."""
    result = post_form(f"https://login.microsoftonline.com/{settings['ENTRA_TENANT_ID']}/oauth2/v2.0/token", {
        "client_id": settings["GRAPH_CLIENT_ID"], "client_secret": settings["GRAPH_CLIENT_SECRET"],
        "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"})
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

    A 302/303 from Graph means it authorised the report and issued a download link, so it counts as 200;
    the link (on a reports host) is not fetched.
    """
    request = urllib.request.Request("https://graph.microsoft.com" + path,
                                     headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
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


def run_checks(settings, wait):
    """Test every area; while some are denied, retry with fresh tokens for up to `wait` seconds."""
    deadline = time.monotonic() + wait
    while True:
        token = app_token(settings)
        results = [(label, permission, *graph_status(path, token)) for label, permission, path in CHECKS]
        denied = [r for r in results if r[2] in (401, 403)]
        if not denied or time.monotonic() >= deadline:
            return results
        print(f"  {len(denied)} area(s) not live yet; Microsoft can take a few minutes. Retrying in 30s…",
              flush=True)
        time.sleep(30)


def explain(permission, status, code):
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
    args = parser.parse_args()
    settings = deployment.load_settings(args.env_file)
    app_id = settings["GRAPH_CLIENT_ID"]
    names = deployment.READ_PERMISSIONS
    progress = deployment.Progress(2 if args.check_only else 6)
    changed = False
    if not args.check_only:
        if not shutil.which("az"):
            raise SetupError("Install Microsoft's Azure CLI, then sign in with az login --tenant TENANT_ID.")
        progress.step("Checking your Azure sign-in")
        account = cli(["account", "show"])
        if identifier(account.get("tenantId")) != settings["ENTRA_TENANT_ID"]:
            raise SetupError("Azure CLI is signed in to a different tenant than AIO. "
                             "Run az login --tenant " + settings["ENTRA_TENANT_ID"])
        print("Signed in as " + str(account.get("user", {}).get("name", "unknown")))
        progress.step(f"Requesting the {len(names)} read-only permissions on cloudshift inventory")
        added = deployment.ensure_read_permissions(app_id)
        print("  added: " + ", ".join(added) if added else "  all already requested")
        progress.step("Granting admin consent for exactly those permissions")
        try:
            granted = deployment.grant_read_permissions(app_id)
        except SetupError:
            raise SetupError("Admin consent failed. Sign in as a Global Administrator or Privileged Role "
                             "Administrator (az login --tenant " + settings["ENTRA_TENANT_ID"] + ") and rerun, "
                             "or grant it in Entra → App registrations → cloudshift inventory → API "
                             "permissions → Grant admin consent.") from None
        print("  granted: " + ", ".join(granted) if granted else "  already granted")
        changed = bool(added or granted)
    progress.step("Getting an app sign-in for cloudshift inventory")
    app_token(settings)
    print("  signed in")
    progress.step("Testing each AIO area against Microsoft Graph", "under 1 min; up to 5 min after new consent")
    # Only wait for propagation when this run changed access; otherwise a denial is the real answer.
    results = run_checks(settings, WAIT_SECONDS if changed else 0)
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
    width = max(len(label) for label, *_ in results)
    for label, permission, status, code in results:
        print(f"  {'✓' if status == 200 else '✗'} {label.ljust(width)}  {explain(permission, status, code)}")
    live = sum(status == 200 for *_, status, _ in results)
    print()
    print(f"{live} of {len(results)} areas are live.")
    if live < len(results):
        print("Rerun later with --check-only to test again without changing anything.")
    sys.exit(0 if live == len(results) else 2)


if __name__ == "__main__":
    try:
        main()
    except (SetupError, OSError, KeyError, TypeError, ValueError):
        error = sys.exc_info()[1]
        print("Permissions stopped: " + (str(error) if isinstance(error, SetupError) else
              "Local failure; configuration values and response details were not logged."), file=sys.stderr)
        sys.exit(1)
