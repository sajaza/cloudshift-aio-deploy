#!/usr/bin/env python3
"""Host cloudshift AIO on Azure Container Apps through the signed-in Azure CLI session (macOS, Linux or Windows).

Reads the private configuration from register-entra.py, stores the three secrets in Key Vault
(one fewer with --federation),
builds the image in Azure Container Registry, deploys infra/main.bicep, and adds the hosted
sign-in redirect to the operators registration. Never prints credential values.
With --federation the inventory app trusts the Container App's managed identity (workload identity
federation) and needs no client secret; --remove-secrets then deletes its old secrets on request.
Python standard library only. Run --plan to inspect changes without Azure access.
"""
import argparse
import datetime as dt
import getpass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from graph_permissions import (EXCHANGE_APP_ID, EXCHANGE_READ_PERMISSIONS, EXCHANGE_ROLE_GROUP, GRAPH_APP_ID,
                               MESSAGE_TRACE_APP_ID, READ_PERMISSIONS)

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "infra" / "main.bicep"
DEFAULT_ENV = ROOT / ".env.entra.generated"
PROVIDERS = ("Microsoft.App", "Microsoft.OperationalInsights", "Microsoft.ContainerRegistry",
             "Microsoft.KeyVault", "Microsoft.ManagedIdentity")
REQUIRED = ("NEXTAUTH_SECRET", "ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "GRAPH_CLIENT_ID")
# At least one is required: listed operator object IDs, or an Entra group whose members are operators.
OPERATOR_IDS, OPERATOR_GROUP = "CLOUDSHIFT_OPERATOR_IDS", "CLOUDSHIFT_OPERATOR_GROUP_ID"
# Key Vault secret name -> environment variable. Must match secretNames in main.bicep.
SECRETS = {"nextauth-secret": "NEXTAUTH_SECRET", "entra-client-secret": "ENTRA_CLIENT_SECRET",
           "graph-client-secret": "GRAPH_CLIENT_SECRET"}
# App registration -> (Key Vault secret name, setting holding its client secret, setting holding its app ID).
# Apps in FEDERATED_APPS need no secret when workload identity federation is on. The operators app
# already gets a federated identity credential; adding "operators" here later drops entra-client-secret
# the same way, once sign-in uses federatedClientAssertion().
APP_SECRETS = {"inventory": ("graph-client-secret", "GRAPH_CLIENT_SECRET", "GRAPH_CLIENT_ID"),
               "operators": ("entra-client-secret", "ENTRA_CLIENT_SECRET", "ENTRA_CLIENT_ID")}
FEDERATED_APPS = ("inventory",)
# Deploy-time switch kept in the private settings file; the app itself reads FEDERATED_ENV.
FEDERATION = "CLOUDSHIFT_USE_FEDERATION"
FEDERATED_ENV = "CLOUDSHIFT_FEDERATED_IDENTITY_CLIENT_ID"
FIC_NAME = "cloudshift-aio-container"
FIC_AUDIENCE = "api://AzureADTokenExchange"
FIC_LIMIT = 20  # Entra allows at most 20 federated identity credentials per application.
# Optional "Add user" feature, set up by enable-user-admin.py. It writes with the signed-in operator's
# delegated Graph token, so it adds no app, secret or application permission.
USER_ADMIN_FLAG = "CLOUDSHIFT_ENABLE_USER_ADMIN"
# Settings of the retired app-only "cloudshift user admin" registration: ignored, never uploaded.
LEGACY_USER_ADMIN = ("USERADMIN_CLIENT_ID", "USERADMIN_CLIENT_SECRET")
# Optional Azure Virtual Desktop area, set up by enable-avd.py. It calls Azure Resource Manager with the
# signed-in operator's delegated token (their own Azure RBAC), so AIO gets no Azure role of its own.
AVD_FLAG = "CLOUDSHIFT_ENABLE_AVD"
# Features the hosted template does not configure yet; a local-only setting is ignored, not copied.
UNSUPPORTED = ("CLOUDSHIFT_GDAP_DISCOVERY", "CLOUDSHIFT_PARTNER_DISCOVERY", "CLOUDSHIFT_ENABLE_DEPLOYMENTS")
CALLBACK = "/api/auth/callback/azure-ad"
# Local-development sign-in redirect that register-entra.py adds without --for-hosting. A hosted install
# drops it from cloudshift operators: an authorization code sent to a localhost listener on an operator's
# machine is not something production sign-in should accept. Local development uses its own registration.
LOCAL_REDIRECT = "http://localhost:3000" + CALLBACK
# Display name register-entra.py gives the client secrets it creates; --remove-secrets deletes only these
# unless --all-credentials is passed.
AIO_SECRET_NAME = "cloudshift local setup"
# Resume file written by register-entra.py next to the settings file; --remove-secrets scrubs secret values.
STATE_FILE = ".env.registration-state.json"
NAME = re.compile(r"^[a-z][a-z0-9-]{1,22}[a-z0-9]$")


class SetupError(Exception):
    pass


def identifier(value):
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise SetupError("Expected a valid tenant, application, or operator UUID.") from None


def parse_env(text):
    """Read KEY=value lines as written by register-entra.py; values are never echoed on error."""
    values = {}
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key.strip()):
            raise SetupError(f"Unreadable configuration line {number}.")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        elif value[:1] in ("'", '"'):
            raise SetupError(f"Unterminated quoted value on configuration line {number}.")
        values[key.strip()] = value.replace("\\$", "$")
    return values


def load_settings(path, check_user_admin=True, federation=None, check_avd=True):
    """federation: True/False overrides the file's CLOUDSHIFT_USE_FEDERATION; None uses the file."""
    if path.is_symlink() or not path.is_file():
        raise SetupError(f"Configuration file {path.name} not found. Run scripts/register-entra.py first.")
    # Windows protects files in the user profile with ACLs rather than mode bits.
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise SetupError(f"Configuration file must be private: run chmod 600 {path.name}.")
    values = parse_env(path.read_text(encoding="utf-8"))
    if values.get("CLOUDSHIFT_DEMO_MODE", "false") != "false":
        raise SetupError("Demo mode cannot be hosted. Use the live configuration from register-entra.py.")
    flag = values.get(FEDERATION, "false") or "false"
    if flag not in ("true", "false"):
        raise SetupError(FEDERATION + " must be 'true' or 'false'.")
    values[FEDERATION] = "true" if (flag == "true" if federation is None else federation) else "false"
    missing = [key for key in REQUIRED + tuple(secret_settings(values)) if not values.get(key)]
    if missing:
        hint = (" (or deploy with --federation)" if "GRAPH_CLIENT_SECRET" in missing else "")
        raise SetupError("Missing configuration: " + ", ".join(missing) + hint)
    if len(values["NEXTAUTH_SECRET"]) < 32:
        raise SetupError("NEXTAUTH_SECRET must contain at least 32 characters.")
    for key in ("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "GRAPH_CLIENT_ID"):
        values[key] = identifier(values[key])
    values[OPERATOR_IDS] = ",".join(
        identifier(v.strip()) for v in values.get(OPERATOR_IDS, "").split(",") if v.strip())
    if values.get(OPERATOR_GROUP):
        try:
            values[OPERATOR_GROUP] = identifier(values[OPERATOR_GROUP])
        except SetupError:
            raise SetupError(OPERATOR_GROUP + " must be the group's object ID (a UUID), not its name.") from None
    else:
        values[OPERATOR_GROUP] = ""
    if not values[OPERATOR_IDS] and not values[OPERATOR_GROUP]:
        raise SetupError("Missing configuration: " + OPERATOR_IDS + " or " + OPERATOR_GROUP)
    try:
        tenants = json.loads(values.get("CLOUDSHIFT_TENANTS_JSON") or "[]")
    except json.JSONDecodeError:
        raise SetupError("CLOUDSHIFT_TENANTS_JSON must be valid JSON.") from None
    if not isinstance(tenants, list) or not all(isinstance(t, dict) and t.get("name") for t in tenants):
        raise SetupError("CLOUDSHIFT_TENANTS_JSON must be a list of tenants with id and name.")
    for tenant in tenants:
        tenant["id"] = identifier(tenant.get("id"))
    values["CLOUDSHIFT_TENANTS_JSON"] = json.dumps(tenants, separators=(",", ":"))
    if check_user_admin:
        check_user_admin_settings(values)
    if check_avd:
        check_avd_settings(values)
    legacy_user_admin_note(values, path)
    return values


def federated(settings):
    return settings.get(FEDERATION) == "true"


def secret_settings(settings):
    """Settings holding client secrets that this deployment still needs."""
    return [env for app, (_, env, _) in APP_SECRETS.items()
            if not (federated(settings) and app in FEDERATED_APPS)]


def app_is_federated(app):
    """True when a deployed Container App already authenticates the inventory app by federation."""
    containers = (app or {}).get("properties", {}).get("template", {}).get("containers") or []
    return any(isinstance(item, dict) and item.get("name") == FEDERATED_ENV and item.get("value")
               for container in containers for item in container.get("env", []) or [])


def user_admin_enabled(settings):
    return settings.get(USER_ADMIN_FLAG, "false") == "true"


def check_user_admin_settings(values):
    """The Add user flag must be 'true' or 'false'; it needs no credentials of its own."""
    flag = values.get(USER_ADMIN_FLAG, "false")
    if flag not in ("true", "false", ""):
        raise SetupError(USER_ADMIN_FLAG + " must be 'true' or 'false'.")


def avd_enabled(settings):
    return settings.get(AVD_FLAG, "false") == "true"


def check_avd_settings(values):
    """The Azure Virtual Desktop flag must be 'true' or 'false'; it needs no credentials of its own."""
    if values.get(AVD_FLAG, "false") not in ("true", "false", ""):
        raise SetupError(AVD_FLAG + " must be 'true' or 'false'.")


def legacy_app_id(values):
    """Client ID of the retired 'cloudshift user admin' app named in an old file, if readable."""
    try:
        return identifier(values.get("USERADMIN_CLIENT_ID"))
    except SetupError:
        return None


def legacy_user_admin_note(values, path):
    """Old files may still name the retired write app. Its settings are dropped (never deployed or
    uploaded) and a note says how to delete it. Prints the client ID only, never the secret."""
    if not any(values.get(key) for key in LEGACY_USER_ADMIN):
        return
    app_id = legacy_app_id(values)
    for key in LEGACY_USER_ADMIN:
        values.pop(key, None)
    print(f"Note: {path.name} still has USERADMIN_ settings for the retired 'cloudshift user admin' app. "
          "They are ignored: Add user now writes as the signed-in operator.")
    how = f"az ad app delete --id {app_id}" if app_id else "Entra → App registrations → cloudshift user admin → Delete"
    print("  Delete that app registration so its application permission and secret stop working: " + how)
    print("  Then remove the USERADMIN_ lines (scripts/enable-user-admin.py does that for you).")


def template_parameters(settings, name, deployer_id, image="", domain=None, certificate_id=None):
    """Bicep parameters. Secrets are deliberately absent; the app reads them from Key Vault."""
    parameters = {
        "customDomain": domain or "", "customDomainCertificateId": certificate_id or "",
        "name": name, "deployerObjectId": deployer_id, "deployApp": bool(image), "image": image,
        "entraTenantId": settings["ENTRA_TENANT_ID"], "entraClientId": settings["ENTRA_CLIENT_ID"],
        "graphClientId": settings["GRAPH_CLIENT_ID"], "operatorIds": settings[OPERATOR_IDS],
        "operatorGroupId": settings.get(OPERATOR_GROUP, ""),
        "tenantsJson": settings["CLOUDSHIFT_TENANTS_JSON"],
        # Only switches the Add user feature on; writes use each operator's delegated token.
        "enableUserAdmin": user_admin_enabled(settings),
        # Only switches the Azure Virtual Desktop area on; Azure calls use each operator's delegated token.
        "enableAvd": avd_enabled(settings),
        # The template reads the identity's client ID itself, so it always matches the identity it attaches.
        "useFederation": federated(settings),
    }
    return {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
            "contentVersion": "1.0.0.0", "parameters": {k: {"value": v} for k, v in parameters.items()}}


def merged_redirects(existing, *app_urls):
    """Existing redirect URIs plus the hosted callbacks; the local-development URI is dropped (hosted only)."""
    redirects = [uri for uri in existing if uri != LOCAL_REDIRECT]
    for app_url in app_urls:
        target = app_url.rstrip("/") + CALLBACK
        if not target.startswith("https://"):
            raise SetupError("Hosted sign-in requires an HTTPS address.")
        if target not in redirects:
            redirects.append(target)
    return redirects


HOSTNAME = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,}[a-z]{2,63}$")


def normalize_domain(value):
    """A subdomain such as aio.contoso.com, or None for the generic address."""
    text = (value or "").strip().lower()
    if text in ("", "generic", "none"):
        return None
    text = re.sub(r"^https?://", "", text).split("/", 1)[0].rstrip(".")
    if not HOSTNAME.fullmatch(text):
        raise SetupError("The web address must be a subdomain such as aio.contoso.com "
                         "(a bare domain like contoso.com cannot use a CNAME record).")
    return text


def app_details(group, name):
    """The existing Container App, or None on a first install."""
    try:
        return cli(["containerapp", "show", "--resource-group", group, "--name", name])
    except SetupError:
        return None


def bound_domain(app):
    """(hostname, certificate ID) of a custom domain bound with a certificate, if any."""
    domains = ((app or {}).get("properties", {}).get("configuration", {})
               .get("ingress", {}).get("customDomains") or [])
    for domain in domains:
        if domain.get("bindingType") == "SniEnabled" and domain.get("certificateId"):
            return domain.get("name"), domain["certificateId"]
    return None, None


def dns_records(domain, generic_host, verification_id):
    return [("CNAME", domain, generic_host), ("TXT", "asuid." + domain, verification_id)]


def choose_domain(requested, existing):
    if requested is not None:
        return normalize_domain(requested)
    if not sys.stdin.isatty():
        return existing
    default = existing or "generic address"
    answer = input(f"Custom web address for AIO, e.g. aio.contoso.com [Enter = {default}; "
                   f"type generic for the Azure address]: ")
    return existing if not answer.strip() else normalize_domain(answer)


def bind_domain(group, name, environment, domain, generic_host, verification_id):
    """Show the DNS records, then attach the domain with a free managed certificate."""
    print("  Add these two records at your DNS provider (many providers want only the part before")
    print("  your domain, e.g. 'aio' and 'asuid.aio'):")
    for kind, host, value in dns_records(domain, generic_host, verification_id):
        print(f"    {kind:<5} {host}  →  {value}")
    interactive = sys.stdin.isatty()
    while True:
        if interactive:
            answer = input("  Press Enter once both records exist (type skip to keep the generic address): ")
            if answer.strip().lower() == "skip":
                return None
        try:
            try:
                cli(["containerapp", "hostname", "add", "--hostname", domain,
                     "--resource-group", group, "--name", name])
            except SetupError:
                pass  # Already added by an earlier attempt; binding below reports real problems.
            cli(["containerapp", "hostname", "bind", "--hostname", domain, "--resource-group", group,
                 "--name", name, "--environment", environment, "--validation-method", "CNAME"], timeout=1800)
        except SetupError:
            print("  Azure could not verify the records yet. DNS changes can take a few minutes to appear.")
            if not interactive:
                return None
            continue
        _, certificate_id = bound_domain(app_details(group, name))
        if certificate_id:
            return certificate_id
        print("  The certificate is not ready yet; try again in a minute.")
        if not interactive:
            return None


def private_temp(directory, name, text):
    path = Path(directory) / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


class Progress:
    """Numbered steps with a step bar and a live elapsed timer; plain lines when not a terminal."""
    WIDTH = 20

    def __init__(self, total):
        self.total, self.number, self.started = total, 0, time.monotonic()
        self.live = sys.stdout.isatty()

    def step(self, text, typical=""):
        self.number += 1
        filled = round(self.WIDTH * (self.number - 1) / self.total)
        bar = "█" * filled + "░" * (self.WIDTH - filled)
        hint = f" (usually {typical})" if typical else ""
        print(f"\n{bar} step {self.number}/{self.total}: {text}{hint}", flush=True)

    def finish(self):
        print(f"{'█' * self.WIDTH} all {self.total} steps done in {elapsed(self.started)}", flush=True)


def elapsed(started):
    seconds = int(time.monotonic() - started)
    return f"{seconds // 60}m {seconds % 60:02d}s" if seconds >= 60 else f"{seconds}s"


def waiting(work):
    """Run work() while redrawing a spinner and elapsed time, so long Azure calls visibly progress."""
    if not sys.stdout.isatty():
        return work()
    outcome = {}

    def run():
        try:
            outcome["value"] = work()
        except BaseException as error:  # re-raised on the main thread
            outcome["error"] = error

    worker = threading.Thread(target=run, daemon=True)
    started = time.monotonic()
    worker.start()
    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    tick = 0
    while worker.is_alive():
        print(f"\r  {frames[tick % len(frames)]} working… {elapsed(started)}   ", end="", flush=True)
        tick += 1
        worker.join(0.2)
    print("\r" + " " * 40 + "\r", end="", flush=True)
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


def cli(args, timeout=300):
    # On Windows the CLI is az.cmd, which only runs when called by its resolved path.
    az = shutil.which("az") or "az"
    try:
        result = waiting(lambda: subprocess.run(
            [az, *args, "--only-show-errors", "--output", "json"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, check=False))
    except (subprocess.TimeoutExpired, OSError):
        raise SetupError("Azure CLI request failed or timed out; no response details were logged.") from None
    if result.returncode:
        # Output can include configuration values. Name the step, not the response.
        raise SetupError("Azure CLI step failed: az " + " ".join(args[:2]) +
                         ". Check login, subscription role, and the Azure portal; response details are suppressed.")
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        raise SetupError("Azure CLI returned an unexpected response; response details are suppressed.") from None


def deploy(group, settings, name, deployer_id, image="", domain=None, certificate_id=None):
    with tempfile.TemporaryDirectory(prefix="cloudshift-deploy-") as directory:
        parameters = private_temp(directory, "parameters.json", json.dumps(
            template_parameters(settings, name, deployer_id, image, domain, certificate_id)))
        result = cli(["deployment", "group", "create", "--resource-group", group,
                      "--name", f"{name}-{'app' if image else 'base'}", "--template-file", str(TEMPLATE),
                      "--parameters", "@" + str(parameters)], timeout=1800)
    outputs = result.get("properties", {}).get("outputs", {})
    return {key: value.get("value") for key, value in outputs.items()}


RESOURCE_NAMES = {GRAPH_APP_ID: "Microsoft Graph", EXCHANGE_APP_ID: "Office 365 Exchange Online"}


def graph_role_ids(app_roles, names=READ_PERMISSIONS, resource=GRAPH_APP_ID):
    roles = {}
    for name in names:
        matches = [r for r in app_roles if r.get("value") == name and r.get("isEnabled")
                   and "Application" in r.get("allowedMemberTypes", [])]
        if len(matches) != 1:
            raise SetupError(RESOURCE_NAMES[resource] + " application permission unavailable: " + name)
        roles[name] = identifier(matches[0]["id"])
    return roles


def merged_access(existing, roles, resource=GRAPH_APP_ID):
    """Add missing roles of one resource API (Graph by default) to requiredResourceAccess. Never removes or
    changes other entries."""
    access = json.loads(json.dumps(existing or []))
    graph = next((entry for entry in access if entry.get("resourceAppId") == resource), None)
    if graph is None:
        graph = {"resourceAppId": resource, "resourceAccess": []}
        access.append(graph)
    present = {item.get("id") for item in graph.setdefault("resourceAccess", []) if item.get("type") == "Role"}
    added = []
    for name, role_id in roles.items():
        if role_id not in present:
            graph["resourceAccess"].append({"id": role_id, "type": "Role"})
            added.append(name)
    return access, added


def ensure_read_permissions(app_id):
    """Make sure the inventory app requests every AIO read permission. Returns the names added."""
    return ensure_permissions(app_id, READ_PERMISSIONS)


def ensure_exchange_permissions(app_id):
    """Make the inventory app request Exchange.ManageAsApp on Office 365 Exchange Online (add-only). It only
    lets the app call Exchange Online; its Exchange role (View-Only Organization Management) decides what it
    can do there. Returns the names added."""
    return ensure_permissions(app_id, EXCHANGE_READ_PERMISSIONS, EXCHANGE_APP_ID)


def ensure_permissions(app_id, names, resource=GRAPH_APP_ID):
    """Make the app request these application roles of one resource API (add-only). Returns the names added."""
    roles = graph_role_ids(cli(["ad", "sp", "show", "--id", resource]).get("appRoles", []), names, resource)
    current = cli(["ad", "app", "show", "--id", app_id]).get("requiredResourceAccess", [])
    access, added = merged_access(current, roles, resource)
    if added:
        with tempfile.TemporaryDirectory(prefix="cloudshift-deploy-") as directory:
            body = private_temp(directory, "body.json", json.dumps({"requiredResourceAccess": access}))
            cli(["rest", "--method", "PATCH",
                 "--url", f"https://graph.microsoft.com/v1.0/applications(appId='{identifier(app_id)}')",
                 "--headers", "Content-Type=application/json", "--body", "@" + str(body)])
    return added


def exchange_role_steps(app_id, principal_id=None):
    """Exact Exchange Online PowerShell an Exchange Administrator runs once per tenant to give the inventory
    app read-only Exchange access. Exchange role groups cannot be changed through Microsoft Graph, so this is
    printed, never run. Only IDs are printed (no secrets). Without principal_id (another tenant, or no Azure
    CLI sign-in) the enterprise application's object ID is left as a placeholder."""
    app = identifier(app_id)
    principal = identifier(principal_id) if principal_id else "<object ID of cloudshift inventory in Entra → Enterprise applications>"
    return [
        "Connect-ExchangeOnline   # as an Exchange Administrator of this tenant (module ExchangeOnlineManagement)",
        f'New-ServicePrincipal -AppId {app} -ObjectId {principal} -DisplayName "cloudshift inventory"',
        f'Add-RoleGroupMember -Identity "{EXCHANGE_ROLE_GROUP}" -Member {principal}',
        "# Narrower alternative to the role group (same read-only roles, assigned directly):",
        f'#   New-ManagementRoleAssignment -App {principal} -Role "View-Only Configuration"',
        f'#   New-ManagementRoleAssignment -App {principal} -Role "View-Only Recipients"',
        "# To undo later:",
        f'#   Remove-RoleGroupMember -Identity "{EXCHANGE_ROLE_GROUP}" -Member {principal}',
        f"#   Remove-ServicePrincipal -Identity {principal}",
    ]


def service_principal(app_id):
    """Object ID of the app's enterprise application in this tenant, created if it is missing."""
    found = cli(["ad", "sp", "list", "--filter", f"appId eq '{identifier(app_id)}'"])
    if found:
        return identifier(found[0]["id"])
    return identifier(cli(["ad", "sp", "create", "--id", identifier(app_id)])["id"])


def grant_read_permissions(app_id):
    """Admin-consent exactly the AIO read roles for the inventory app; other requested permissions stay
    unconsented. Needs Global or Privileged Role Administrator. Returns the names newly granted."""
    return grant_app_roles(app_id, READ_PERMISSIONS)


def grant_exchange_permissions(app_id):
    """Admin-consent Exchange.ManageAsApp (Office 365 Exchange Online) for the inventory app. Returns the
    names newly granted. The Exchange role itself is a separate, Exchange-side step (see exchange_role_steps)."""
    return grant_app_roles(app_id, EXCHANGE_READ_PERMISSIONS, EXCHANGE_APP_ID)


def ensure_message_trace_principal():
    """Graph message trace needs Microsoft's message trace service principal in the tenant (documented
    prerequisite). Creates it if missing; it grants nothing to cloudshift. Returns its object ID."""
    return service_principal(MESSAGE_TRACE_APP_ID)


def grant_app_roles(app_id, names, resource=GRAPH_APP_ID):
    """Admin-consent exactly these application roles of one resource API (Graph by default), one
    appRoleAssignment each; nothing else is consented or removed. Needs Global or Privileged Role
    Administrator. Returns the names newly granted."""
    graph = cli(["ad", "sp", "show", "--id", resource])
    graph_id = identifier(graph.get("id"))
    roles = graph_role_ids(graph.get("appRoles", []), names, resource)
    principal = service_principal(app_id)
    url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{principal}/appRoleAssignments"
    current = cli(["rest", "--method", "GET", "--url", url]).get("value", [])
    assigned = {str(item.get("appRoleId")).lower() for item in current if item.get("resourceId") == graph_id}
    granted = []
    with tempfile.TemporaryDirectory(prefix="cloudshift-deploy-") as directory:
        for name, role_id in roles.items():
            if role_id in assigned:
                continue
            body = private_temp(directory, f"grant-{len(granted)}.json", json.dumps(
                {"principalId": principal, "resourceId": graph_id, "appRoleId": role_id}))
            cli(["rest", "--method", "POST", "--url", url,
                 "--headers", "Content-Type=application/json", "--body", "@" + str(body)])
            granted.append(name)
    return granted


def secret_names(settings):
    """Key Vault secret name -> setting, with no secret for an app that uses workload identity
    federation. Add user needs no secret of its own."""
    dropped = {APP_SECRETS[app][0] for app in FEDERATED_APPS} if federated(settings) else set()
    return {name: key for name, key in SECRETS.items() if name not in dropped}


def store_secrets(vault, settings):
    with tempfile.TemporaryDirectory(prefix="cloudshift-deploy-") as directory:
        for secret, key in secret_names(settings).items():
            path = private_temp(directory, secret, settings[key])
            # New role assignments take a few minutes to reach Key Vault.
            for attempt in range(8):
                try:
                    cli(["keyvault", "secret", "set", "--vault-name", vault, "--name", secret,
                         "--file", str(path), "--encoding", "utf-8"])
                    break
                except SetupError:
                    if attempt == 7:
                        raise
                    if attempt == 0:
                        # A secret removed by --remove-secrets is soft-deleted; restore it before rewriting
                        # it (rollback). Fails harmlessly when nothing was deleted.
                        try:
                            cli(["keyvault", "secret", "recover", "--vault-name", vault, "--name", secret])
                        except SetupError:
                            pass
                    print("  waiting for Key Vault access to propagate…")
                    time.sleep(20)
            print(f"  stored {secret}")


def federated_credential(tenant_id, principal_id):
    """The trust Entra checks when the app presents a managed-identity token instead of a secret."""
    return {"name": FIC_NAME, "issuer": f"https://login.microsoftonline.com/{identifier(tenant_id)}/v2.0",
            "subject": identifier(principal_id), "audiences": [FIC_AUDIENCE],
            "description": "cloudshift AIO Container App managed identity (workload identity federation)"}


def ensure_federated_credential(app_id, tenant_id, principal_id):
    """Idempotently trust the managed identity: 'present' when an identical trust exists, 'created', or
    'replaced' when cloudshift-aio-container pointed at a different identity. Other credentials stay."""
    app_id, wanted = identifier(app_id), federated_credential(tenant_id, principal_id)
    current = [item for item in cli(["ad", "app", "federated-credential", "list", "--id", app_id]) or []
               if isinstance(item, dict)]

    def matches(item):
        return (item.get("issuer") == wanted["issuer"] and item.get("subject") == wanted["subject"]
                and FIC_AUDIENCE in (item.get("audiences") or []))

    named = next((item for item in current if item.get("name") == FIC_NAME), None)
    if named and matches(named):
        return "present"
    outcome = "created"
    if named:
        # Name is immutable and issuer+subject must be unique per app: delete, then recreate.
        cli(["ad", "app", "federated-credential", "delete", "--id", app_id,
             "--federated-credential-id", str(named.get("id") or FIC_NAME)])
        current.remove(named)
        outcome = "replaced"
    if any(matches(item) for item in current):
        return "present" if outcome == "created" else outcome
    if len(current) >= FIC_LIMIT:
        raise SetupError(f"The app already has {FIC_LIMIT} federated identity credentials, Entra's limit; "
                         "remove an unused one in Entra → App registrations → Certificates & secrets.")
    with tempfile.TemporaryDirectory(prefix="cloudshift-deploy-") as directory:
        body = private_temp(directory, "credential.json", json.dumps(wanted))
        cli(["ad", "app", "federated-credential", "create", "--id", app_id, "--parameters", "@" + str(body)])
    return outcome


def write_setting(path, key, value):
    """Replace, append (value) or drop (None) one KEY='value' line of the private settings file; every
    other line is kept. Atomic, mode 0600."""
    lines, found = [], False
    for line in path.read_text(encoding="utf-8").splitlines():
        name = line.strip().removeprefix("export ").partition("=")[0].strip()
        if name == key:
            if value is not None and not found:
                lines.append(f"{key}='{value}'")
            found = True
        else:
            lines.append(line)
    if not found and value is not None:
        lines.append(f"{key}='{value}'")
    fd, temporary = tempfile.mkstemp(prefix=".env.deploy-", dir=path.parent)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def scrub_registration_state(env_path):
    """Drop every secret value (client secrets and the session secret) from register-entra.py's resume
    file next to env_path; app IDs and secret key IDs stay. Call it only while env_path holds the secrets
    still in use (load_settings requires NEXTAUTH_SECRET and ENTRA_CLIENT_SECRET). True if it changed."""
    path = env_path.parent / STATE_FILE
    if path.is_symlink() or not path.is_file():
        return False
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print(f"  could not read {STATE_FILE}; delete it once you no longer need to rerun register-entra.py")
        return False
    if not isinstance(state, dict):
        return False
    changed = state.pop("session_secret", None) is not None
    for record in (state.get("apps") or {}).values():
        if isinstance(record, dict) and "secret" in record:
            del record["secret"]
            changed = True
    if not changed:
        return False
    fd, temporary = tempfile.mkstemp(prefix=".env.deploy-", dir=path.parent)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(state, indent=2) + "\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def remove_inventory_secrets(app_id, vault, env_path, confirm=None, all_credentials=False, assume_yes=False):
    """Opt-in only (--remove-secrets): delete the inventory app's client secrets that AIO created (display
    name AIO_SECRET_NAME; every password credential with all_credentials), its Key Vault secret
    (soft-deleted, recoverable for 30 days), its line in the settings file and its value in the resume
    file. Other apps' credentials, certificates and federated identity credentials are never touched.
    Without a terminal it refuses unless assume_yes (--yes-remove-secrets) was given."""
    app_id = identifier(app_id)
    kv_secret, setting, _ = APP_SECRETS["inventory"]
    listed = [item for item in cli(["ad", "app", "credential", "list", "--id", app_id]) or []
              if isinstance(item, dict) and item.get("keyId")]
    credentials = [item for item in listed if all_credentials or item.get("displayName") == AIO_SECRET_NAME]
    kept = [item for item in listed if item not in credentials]
    print("  WARNING: this deletes the cloudshift inventory app's client secrets. Afterwards only workload")
    print("  identity federation can authenticate it; rolling back needs a new client secret.")
    for item in credentials:
        print(f"    secret {identifier(item['keyId'])}  {item.get('displayName') or '(no name)'}  "
              f"expires {item.get('endDateTime') or 'unknown'}")
    if kept:
        print(f"  Keeping {len(kept)} client secret(s) AIO did not create (pass --all-credentials to delete them):")
        for item in kept:
            print(f"    secret {identifier(item['keyId'])}  {item.get('displayName') or '(no name)'}")
    print(f"    Key Vault secret {kv_secret} in {vault}, and {setting} in {env_path.name}")
    if confirm is None:
        if sys.stdin.isatty():
            confirm = lambda: input("  Type remove to delete them: ").strip() == "remove"  # noqa: E731
        elif assume_yes:
            confirm = lambda: True  # noqa: E731
        else:
            raise SetupError("--remove-secrets needs a terminal to confirm. To run it without one, add "
                             "--yes-remove-secrets; nothing was removed.")
    if not confirm():
        print("  nothing was removed")
        return []
    removed = []
    for item in credentials:
        key_id = identifier(item["keyId"])
        cli(["ad", "app", "credential", "delete", "--id", app_id, "--key-id", key_id])
        removed.append(key_id)
    try:
        cli(["keyvault", "secret", "delete", "--vault-name", vault, "--name", kv_secret])
    except SetupError:
        print(f"  {kv_secret} was not in Key Vault")
    write_setting(env_path, setting, None)
    print(f"  removed {len(removed)} client secret(s), {kv_secret} and {setting}")
    # The settings file still holds the two secrets in use, so the resume file need not keep any copy.
    if scrub_registration_state(env_path):
        print(f"  removed the stored secret values from {STATE_FILE} (app IDs are kept)")
    return removed


def image_tag():
    try:
        sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True,
                             text=True, timeout=10, check=True).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        sha = "local"
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + (sha or "local")


def build_image(registry, server, tag, local_docker):
    image = f"{server}/cloudshift:{tag}"
    if not local_docker:
        try:
            cli(["acr", "build", "--registry", registry, "--image", f"cloudshift:{tag}",
                 "--file", str(ROOT / "Dockerfile"), str(ROOT)], timeout=1800)
        except SetupError:
            raise SetupError("Image build in Azure failed. Some trial subscriptions block ACR Tasks; "
                             "rerun with --local-docker if Docker Desktop is installed.") from None
        return image
    docker = shutil.which("docker")
    if not docker:
        raise SetupError("Docker is not installed; omit --local-docker to build in Azure.")
    cli(["acr", "login", "--name", registry])
    for command in ([docker, "build", "--platform", "linux/amd64", "-t", image, str(ROOT)],
                    [docker, "push", image]):
        if subprocess.run(command, timeout=1800, check=False).returncode:
            raise SetupError("Local Docker build or push failed.")
    return image


IMAGE = re.compile(r"^ghcr\.io/([a-z0-9][a-z0-9-]{0,38})/[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")


def import_image(registry, server, source, token, username=None):
    """Copy a published private image into this subscription's registry; the token is used once."""
    match = IMAGE.fullmatch(source)
    if not match:
        raise SetupError("--image must look like ghcr.io/OWNER/NAME:TAG.")
    # The token owner's GitHub username; defaults to the image owner.
    username = username or match.group(1)
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", username):
        raise SetupError("--image-user must be a GitHub username.")
    tag = source.rsplit(":", 1)[1] + "-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S")
    try:
        # az acr import only accepts the password as an argument; it is not printed or stored.
        cli(["acr", "import", "--name", registry, "--source", source, "--image", f"cloudshift:{tag}",
             "--username", username, "--password", token, "--force"], timeout=1800)
    except SetupError:
        raise SetupError("Could not copy the cloudshift image. Check the pull token is current and has "
                         "read:packages, then rerun.") from None
    return f"{server}/cloudshift:{tag}"


def image_token():
    token = os.environ.get("CLOUDSHIFT_IMAGE_TOKEN") or getpass.getpass("Image pull token (input hidden): ")
    if not re.fullmatch(r"[A-Za-z0-9_]{20,255}", token.strip()):
        raise SetupError("That does not look like a GitHub token; nothing was sent.")
    return token.strip()


def plan(args):
    print(f"Resource group {args.resource_group} in {args.location}: register providers, then create")
    print("  Log Analytics, managed identity, container registry, Key Vault (RBAC), Container Apps environment.")
    print("Upload NEXTAUTH_SECRET, ENTRA_CLIENT_SECRET and GRAPH_CLIENT_SECRET to Key Vault from private temp files.")
    print("If the configuration has " + USER_ADMIN_FLAG + "='true' (set by enable-user-admin.py), turn on Add")
    print("  user: it writes as the signed-in operator (delegated, their own Entra role); no extra secret.")
    print("If the configuration has " + AVD_FLAG + "='true' (set by enable-avd.py), turn on the Azure Virtual")
    print("  Desktop area: it calls Azure as the signed-in operator (their own Azure roles); AIO gets no Azure role.")
    if args.image:
        print(f"Copy the published image {args.image} into the new registry with your pull token.")
    else:
        print("Build the image " + ("locally with Docker" if args.local_docker else "with ACR Tasks") + " and push it.")
    print(f"Create Container App '{args.name}': one replica, HTTPS only, secrets by Key Vault reference.")
    print("Ask for a custom web address (or use --domain); show its CNAME/TXT records, bind a free managed")
    print("  certificate, and keep that domain on every later redeploy.")
    print("Add https://<app address>" + CALLBACK + " to cloudshift operators; keep existing redirects.")
    print(f"Add any of the {len(READ_PERMISSIONS)} read-only Graph permissions and {EXCHANGE_READ_PERMISSIONS[0]} (Office 365")
    print("  Exchange Online) that cloudshift inventory is missing; never remove any. Its Exchange role is a")
    print("  separate Exchange PowerShell step that grant-permissions.py prints.")
    print("With --grant-consent, admin-consent exactly those permissions before the app starts.")
    print("If the configuration has " + OPERATOR_GROUP + ", members of that Entra group may also sign in.")
    print("With --federation (kept once used): add the federated identity credential " + FIC_NAME + " (issuer")
    print("  https://login.microsoftonline.com/<tenant>/v2.0, subject = the managed identity's principal ID,")
    print("  audience " + FIC_AUDIENCE + ") to cloudshift inventory and cloudshift operators; do not upload")
    print("  graph-client-secret and do not reference it from the app. --no-federation goes back to the secret.")
    print("With --remove-secrets (an install already running federated): list, confirm, then delete only the")
    print("  inventory app's client secrets named '" + AIO_SECRET_NAME + "' (--all-credentials: all of them) and")
    print("  the graph-client-secret Key Vault secret. Never automatic: needs a typed confirmation at a")
    print("  terminal, or --yes-remove-secrets.")
    print("Remove the local-development redirect " + LOCAL_REDIRECT + " from cloudshift operators.")
    print("Customer onboarding stays manual.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resource-group", default="cloudshift-rg")
    parser.add_argument("--location", default="uksouth", help="Azure region, for example uksouth or eastus")
    parser.add_argument("--name", default="cloudshift", help="Container App name (lowercase, hyphens)")
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV, help="Live configuration file")
    parser.add_argument("--subscription", help="Subscription ID or name; defaults to the CLI's current one")
    parser.add_argument("--local-docker", action="store_true", help="Build with local Docker instead of ACR Tasks")
    parser.add_argument("--image", help="Use a published image (ghcr.io/OWNER/NAME:TAG) instead of building")
    parser.add_argument("--grant-consent", action="store_true",
                        help="Grant tenant-wide admin consent for the inventory app (needs an admin role)")
    parser.add_argument("--image-user", help="GitHub username that owns the pull token (default: image owner)")
    parser.add_argument("--domain", help="Custom web address such as aio.contoso.com, or 'generic' "
                        "(default: ask, keeping any domain already in use)")
    parser.add_argument("--plan", action="store_true", help="Show changes without logging in or changing Azure")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--federation", action="store_true",
                      help="No inventory client secret: trust the Container App's managed identity instead")
    mode.add_argument("--no-federation", action="store_true",
                      help="Go back to the inventory client secret (rollback; needs GRAPH_CLIENT_SECRET)")
    parser.add_argument("--remove-secrets", action="store_true",
                        help="After a federated install works: delete the inventory app's old client secrets")
    parser.add_argument("--yes-remove-secrets", action="store_true",
                        help="With --remove-secrets: confirm without a terminal (scripts, pipelines)")
    parser.add_argument("--all-credentials", action="store_true",
                        help="With --remove-secrets: delete every inventory client secret, not only AIO's")
    args = parser.parse_args()
    if (args.yes_remove_secrets or args.all_credentials) and not args.remove_secrets:
        raise SetupError("--yes-remove-secrets and --all-credentials only apply with --remove-secrets.")
    if not NAME.fullmatch(args.name):
        raise SetupError("--name must be 3-24 lowercase letters, digits or hyphens, starting with a letter.")
    if args.plan:
        plan(args)
        return
    if args.remove_secrets and not args.yes_remove_secrets and not sys.stdin.isatty():
        # Refuse before changing Azure, instead of confirming silently at the end of the deploy.
        raise SetupError("--remove-secrets needs a terminal to confirm. To run it without one, add "
                         "--yes-remove-secrets; nothing was changed.")
    choice = True if args.federation else False if args.no_federation else None
    if args.remove_secrets and choice is False:
        raise SetupError("--remove-secrets needs workload identity federation; it cannot be used with --no-federation.")
    settings = load_settings(args.env_file, federation=choice)
    token = image_token() if args.image else None
    for key in UNSUPPORTED:
        if settings.get(key) == "true":
            print(f"Note: {key} is not configured by the hosted template and stays off.")
    if not shutil.which("az"):
        raise SetupError("Install Microsoft's Azure CLI, then sign in with az login --tenant TENANT_ID.")
    progress = Progress(8)
    progress.step("Checking your Azure sign-in")
    if args.subscription:
        cli(["account", "set", "--subscription", args.subscription])
    account = cli(["account", "show"])
    if identifier(account.get("tenantId")) != settings["ENTRA_TENANT_ID"]:
        raise SetupError("Azure CLI is signed in to a different tenant than the operator registration.")
    print(f"Subscription: {account.get('name')} ({account.get('id')})")
    existing_app = app_details(args.resource_group, args.name)
    was_federated = app_is_federated(existing_app)
    if choice is None and was_federated and not federated(settings):
        # Never fall back to a secret silently: an install that runs federated stays federated.
        settings = load_settings(args.env_file, federation=True)
        print("This install uses workload identity federation; keeping it (rerun with --no-federation to undo).")
    if args.remove_secrets and not (federated(settings) and was_federated):
        raise SetupError("--remove-secrets only runs on an install that already runs federated. Deploy with "
                         "--federation, sign in and check data appears, then rerun with --remove-secrets.")
    if federated(settings):
        progress.total += 1
    if args.remove_secrets:
        progress.total += 1
    existing_domain, existing_certificate = bound_domain(existing_app)
    domain = choose_domain(args.domain, existing_domain)
    certificate_id = existing_certificate if domain and domain == existing_domain else None
    if domain and not certificate_id:
        progress.total += 1
    deployer_id = identifier(cli(["ad", "signed-in-user", "show"]).get("id"))
    progress.step("Registering Azure resource providers", "seconds; a few minutes on a new subscription")
    for number, namespace in enumerate(PROVIDERS, 1):
        print(f"  {namespace} ({number}/{len(PROVIDERS)})", flush=True)
        cli(["provider", "register", "--namespace", namespace, "--wait"], timeout=900)
    cli(["group", "create", "--name", args.resource_group, "--location", args.location])
    progress.step("Creating registry, Key Vault, identity and environment", "3–6 min")
    base = deploy(args.resource_group, settings, args.name, deployer_id)
    progress.step("Storing secrets in Key Vault " + base["vaultName"], "under 1 min")
    store_secrets(base["vaultName"], settings)
    if federated(settings):
        progress.step("Trusting the Container App's managed identity (no inventory client secret)", "seconds")
        for app in ("inventory", "operators"):
            app_id = settings[APP_SECRETS[app][2]]
            try:
                outcome = ensure_federated_credential(app_id, settings["ENTRA_TENANT_ID"],
                                                      base["identityPrincipalId"])
            except SetupError:
                if app in FEDERATED_APPS:
                    raise SetupError(f"Could not add the federated identity credential to cloudshift {app}. "
                                     "Run this as an owner of that app registration or an Application "
                                     "Administrator, or rerun with --no-federation.") from None
                print(f"  could not add it to cloudshift {app}; sign-in still uses its client secret")
                continue
            print(f"  cloudshift {app}: {FIC_NAME} {outcome}")
        print("  new trusts can take a few minutes to apply; early Microsoft requests may fail meanwhile")
    # Before the app starts, so its first Graph token already carries every role.
    progress.step(f"Giving cloudshift inventory its {len(READ_PERMISSIONS) + len(EXCHANGE_READ_PERMISSIONS)} "
                  "read-only permissions", "under 1 min")
    consented = permissions_ok = False
    added = []
    try:
        added = (ensure_read_permissions(settings["GRAPH_CLIENT_ID"])
                 + ensure_exchange_permissions(settings["GRAPH_CLIENT_ID"]))
        permissions_ok = True
        print("  added: " + ", ".join(added) if added else "  all permissions already requested")
    except SetupError:
        print("  could not update the app registration with this account; add them in the portal (below)")
    if args.grant_consent:
        try:
            granted = (grant_read_permissions(settings["GRAPH_CLIENT_ID"])
                       + grant_exchange_permissions(settings["GRAPH_CLIENT_ID"]))
            consented = True
            print("  granted admin consent: " + ", ".join(granted) if granted else "  admin consent already granted")
        except SetupError:
            print("  could not grant admin consent with this account; grant it in the portal (below)")
    if args.image:
        progress.step("Copying the cloudshift image", "1–2 min")
        image = import_image(base["registryName"], base["registryServer"], args.image, token, args.image_user)
    else:
        progress.step("Building the cloudshift image", "4–8 min")
        image = build_image(base["registryName"], base["registryServer"], image_tag(), args.local_docker)
    progress.step("Starting the Container App", "2–4 min")
    outputs = deploy(args.resource_group, settings, args.name, deployer_id, image, domain, certificate_id)
    app_url = outputs["appUrl"]
    if domain and not certificate_id:
        progress.step(f"Connecting {domain}", "a few minutes after the DNS records exist")
        app = app_details(args.resource_group, args.name) or {}
        verification_id = app.get("properties", {}).get("customDomainVerificationId", "")
        certificate_id = bind_domain(args.resource_group, args.name, outputs["environmentName"], domain,
                                     app_url.removeprefix("https://"), verification_id)
        if certificate_id:
            print("  certificate issued; switching sign-in to the new address")
            outputs = deploy(args.resource_group, settings, args.name, deployer_id, image, domain, certificate_id)
        else:
            print("  kept the generic address; rerun with --domain " + domain + " once DNS is in place")
    public_url = outputs.get("publicUrl") or app_url
    # Remember the mode so a plain rerun (install.sh) keeps it.
    if parse_env(args.env_file.read_text(encoding="utf-8")).get(FEDERATION, "false") != settings[FEDERATION]:
        write_setting(args.env_file, FEDERATION, settings[FEDERATION])
    if args.remove_secrets:
        progress.step("Removing the inventory app's old client secrets (--remove-secrets)")
        remove_inventory_secrets(settings["GRAPH_CLIENT_ID"], base["vaultName"], args.env_file,
                                 all_credentials=args.all_credentials, assume_yes=args.yes_remove_secrets)
    progress.step("Adding the hosted sign-in address to cloudshift operators (local redirect removed)")
    registration = cli(["ad", "app", "show", "--id", settings["ENTRA_CLIENT_ID"]])
    redirects = merged_redirects(registration.get("web", {}).get("redirectUris", []), app_url, public_url)
    cli(["ad", "app", "update", "--id", settings["ENTRA_CLIENT_ID"], "--web-redirect-uris", *redirects])
    progress.finish()
    print()
    print("cloudshift AIO is deployed: " + public_url)
    if public_url != app_url:
        print("  (the Azure address " + app_url + " still works as a backup)")
    if not permissions_ok:
        print("Entra → App registrations → cloudshift inventory → API permissions: add these Microsoft Graph")
        print("  application permissions: " + ", ".join(READ_PERMISSIONS))
        print("  and Office 365 Exchange Online application permission: " + ", ".join(EXCHANGE_READ_PERMISSIONS))
    if not consented:
        lead = "New permissions need" if added or not permissions_ok else "If you have not already, grant"
        print(f"{lead} admin consent: Entra → App registrations → cloudshift inventory → API permissions")
        print("  → Grant admin consent, then restart the app (Container App → Revisions → Restart).")
        print("  Or rerun this command with --grant-consent as a Global or Privileged Role Administrator.")
    print("Exchange Online blades also need the read-only Exchange role " + EXCHANGE_ROLE_GROUP + ";")
    print("  run scripts/grant-permissions.py to check it and print the exact Exchange PowerShell steps.")
    if federated(settings):
        print("cloudshift inventory uses workload identity federation: the app holds no inventory client secret.")
        if not args.remove_secrets:
            print("  Once sign-in and data work, rerun with --remove-secrets to delete its old client secrets.")
    if user_admin_enabled(settings):
        print("User creation is on. It runs as the signed-in operator, who needs User Administrator in Entra.")
    if avd_enabled(settings):
        print("Azure Virtual Desktop is on. It runs as the signed-in operator, who needs Azure roles on the")
        print("  target subscription or resource group (Contributor + User Access Administrator, or Owner).")
    if settings[OPERATOR_GROUP]:
        print("Members of the Entra group " + settings[OPERATOR_GROUP] + " may sign in, as well as any listed")
        print("  operator IDs. Removing someone from the group takes effect within about 10 minutes.")
    print("Sign in at the address above with an approved operator account.")
    print("The first start can take a minute. Rerun this script to ship a new build.")


if __name__ == "__main__":
    try:
        main()
    except (SetupError, OSError, KeyError, TypeError, ValueError):
        # Catch unexpected failures without printing locals, configuration values, or tracebacks.
        error = sys.exc_info()[1]
        print("Deployment stopped: " + (str(error) if isinstance(error, SetupError) else
              "Local deployment failed; configuration values and response details were not logged."),
              file=sys.stderr)
        sys.exit(1)
