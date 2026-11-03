#!/usr/bin/env python3
"""Host cloudshift AIO on Azure Container Apps through the signed-in Azure CLI session (macOS, Linux or Windows).

Reads the private configuration from register-entra.py, stores the three secrets in Key Vault
(four when user creation is on; see enable-user-admin.py),
builds the image in Azure Container Registry, deploys infra/main.bicep, and adds the hosted
sign-in redirect to the operators registration. Never prints credential values.
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

from graph_permissions import GRAPH_APP_ID, READ_PERMISSIONS

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "infra" / "main.bicep"
DEFAULT_ENV = ROOT / ".env.entra.generated"
PROVIDERS = ("Microsoft.App", "Microsoft.OperationalInsights", "Microsoft.ContainerRegistry",
             "Microsoft.KeyVault", "Microsoft.ManagedIdentity")
REQUIRED = ("NEXTAUTH_SECRET", "ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET",
            "GRAPH_CLIENT_ID", "GRAPH_CLIENT_SECRET", "CLOUDSHIFT_OPERATOR_IDS")
# Key Vault secret name -> environment variable. Must match secretNames in main.bicep.
SECRETS = {"nextauth-secret": "NEXTAUTH_SECRET", "entra-client-secret": "ENTRA_CLIENT_SECRET",
           "graph-client-secret": "GRAPH_CLIENT_SECRET"}
# Optional "cloudshift user admin" write app (User.ReadWrite.All only), set up by enable-user-admin.py.
USER_ADMIN_FLAG = "CLOUDSHIFT_ENABLE_USER_ADMIN"
USER_ADMIN_SECRETS = {"useradmin-client-secret": "USERADMIN_CLIENT_SECRET"}
# Features the hosted template does not configure yet; a local-only setting is ignored, not copied.
UNSUPPORTED = ("CLOUDSHIFT_GDAP_DISCOVERY", "CLOUDSHIFT_PARTNER_DISCOVERY", "CLOUDSHIFT_ENABLE_DEPLOYMENTS")
CALLBACK = "/api/auth/callback/azure-ad"
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


def load_settings(path, check_user_admin=True):
    if path.is_symlink() or not path.is_file():
        raise SetupError(f"Configuration file {path.name} not found. Run scripts/register-entra.py first.")
    # Windows protects files in the user profile with ACLs rather than mode bits.
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise SetupError(f"Configuration file must be private: run chmod 600 {path.name}.")
    values = parse_env(path.read_text(encoding="utf-8"))
    if values.get("CLOUDSHIFT_DEMO_MODE", "false") != "false":
        raise SetupError("Demo mode cannot be hosted. Use the live configuration from register-entra.py.")
    missing = [key for key in REQUIRED if not values.get(key)]
    if missing:
        raise SetupError("Missing configuration: " + ", ".join(missing))
    if len(values["NEXTAUTH_SECRET"]) < 32:
        raise SetupError("NEXTAUTH_SECRET must contain at least 32 characters.")
    for key in ("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "GRAPH_CLIENT_ID"):
        values[key] = identifier(values[key])
    values["CLOUDSHIFT_OPERATOR_IDS"] = ",".join(
        identifier(v.strip()) for v in values["CLOUDSHIFT_OPERATOR_IDS"].split(",") if v.strip())
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
    return values


def user_admin_enabled(settings):
    return settings.get(USER_ADMIN_FLAG, "false") == "true"


def check_user_admin_settings(values):
    """The optional write app must be complete and separate from the sign-in and read-only apps."""
    flag = values.get(USER_ADMIN_FLAG, "false")
    if flag not in ("true", "false", ""):
        raise SetupError(USER_ADMIN_FLAG + " must be 'true' or 'false'.")
    if flag != "true":
        return
    missing = [key for key in ("USERADMIN_CLIENT_ID", "USERADMIN_CLIENT_SECRET") if not values.get(key)]
    if missing:
        raise SetupError("User creation is on but configuration is missing: " + ", ".join(missing) +
                         ". Run scripts/enable-user-admin.py, or set " + USER_ADMIN_FLAG + "='false'.")
    values["USERADMIN_CLIENT_ID"] = identifier(values["USERADMIN_CLIENT_ID"])
    if values["USERADMIN_CLIENT_ID"] in (values["ENTRA_CLIENT_ID"], values["GRAPH_CLIENT_ID"]):
        raise SetupError("USERADMIN_CLIENT_ID must be its own 'cloudshift user admin' registration, "
                         "not the sign-in or inventory app.")


def template_parameters(settings, name, deployer_id, image="", domain=None, certificate_id=None):
    """Bicep parameters. Secrets are deliberately absent; the app reads them from Key Vault."""
    parameters = {
        "customDomain": domain or "", "customDomainCertificateId": certificate_id or "",
        "name": name, "deployerObjectId": deployer_id, "deployApp": bool(image), "image": image,
        "entraTenantId": settings["ENTRA_TENANT_ID"], "entraClientId": settings["ENTRA_CLIENT_ID"],
        "graphClientId": settings["GRAPH_CLIENT_ID"], "operatorIds": settings["CLOUDSHIFT_OPERATOR_IDS"],
        "tenantsJson": settings["CLOUDSHIFT_TENANTS_JSON"],
        # Only the write app's client ID; its secret is a Key Vault reference like the others.
        "enableUserAdmin": user_admin_enabled(settings),
        "userAdminClientId": settings["USERADMIN_CLIENT_ID"] if user_admin_enabled(settings) else "",
    }
    return {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
            "contentVersion": "1.0.0.0", "parameters": {k: {"value": v} for k, v in parameters.items()}}


def merged_redirects(existing, *app_urls):
    redirects = list(existing)
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


def graph_role_ids(app_roles, names=READ_PERMISSIONS):
    roles = {}
    for name in names:
        matches = [r for r in app_roles if r.get("value") == name and r.get("isEnabled")
                   and "Application" in r.get("allowedMemberTypes", [])]
        if len(matches) != 1:
            raise SetupError("Microsoft Graph application permission unavailable: " + name)
        roles[name] = identifier(matches[0]["id"])
    return roles


def merged_access(existing, roles):
    """Add missing Graph roles to requiredResourceAccess. Never removes or changes other entries."""
    access = json.loads(json.dumps(existing or []))
    graph = next((entry for entry in access if entry.get("resourceAppId") == GRAPH_APP_ID), None)
    if graph is None:
        graph = {"resourceAppId": GRAPH_APP_ID, "resourceAccess": []}
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


def ensure_permissions(app_id, names):
    """Make the app request these Graph application roles (add-only). Returns the names added."""
    roles = graph_role_ids(cli(["ad", "sp", "show", "--id", GRAPH_APP_ID]).get("appRoles", []), names)
    current = cli(["ad", "app", "show", "--id", app_id]).get("requiredResourceAccess", [])
    access, added = merged_access(current, roles)
    if added:
        with tempfile.TemporaryDirectory(prefix="cloudshift-deploy-") as directory:
            body = private_temp(directory, "body.json", json.dumps({"requiredResourceAccess": access}))
            cli(["rest", "--method", "PATCH",
                 "--url", f"https://graph.microsoft.com/v1.0/applications(appId='{identifier(app_id)}')",
                 "--headers", "Content-Type=application/json", "--body", "@" + str(body)])
    return added


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


def grant_app_roles(app_id, names):
    """Admin-consent exactly these Graph application roles, one appRoleAssignment each; nothing else is
    consented or removed. Needs Global or Privileged Role Administrator. Returns the names newly granted."""
    graph = cli(["ad", "sp", "show", "--id", GRAPH_APP_ID])
    graph_id = identifier(graph.get("id"))
    roles = graph_role_ids(graph.get("appRoles", []), names)
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
    """Key Vault secret name -> setting; the write app's secret only when user creation is on."""
    return {**SECRETS, **(USER_ADMIN_SECRETS if user_admin_enabled(settings) else {})}


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
                    print("  waiting for Key Vault access to propagate…")
                    time.sleep(20)
            print(f"  stored {secret}")


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
    print("If the configuration has " + USER_ADMIN_FLAG + "='true' (set by enable-user-admin.py), also upload")
    print("  USERADMIN_CLIENT_SECRET as useradmin-client-secret and turn on user creation with the separate")
    print("  'cloudshift user admin' app (User.ReadWrite.All only); with 'false' or unset, it stays off.")
    if args.image:
        print(f"Copy the published image {args.image} into the new registry with your pull token.")
    else:
        print("Build the image " + ("locally with Docker" if args.local_docker else "with ACR Tasks") + " and push it.")
    print(f"Create Container App '{args.name}': one replica, HTTPS only, secrets by Key Vault reference.")
    print("Ask for a custom web address (or use --domain); show its CNAME/TXT records, bind a free managed")
    print("  certificate, and keep that domain on every later redeploy.")
    print("Add https://<app address>" + CALLBACK + " to cloudshift operators; keep existing redirects.")
    print(f"Add any of the {len(READ_PERMISSIONS)} read-only Graph permissions cloudshift inventory is missing; never remove any.")
    print("With --grant-consent, admin-consent exactly those permissions before the app starts.")
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
    args = parser.parse_args()
    if not NAME.fullmatch(args.name):
        raise SetupError("--name must be 3-24 lowercase letters, digits or hyphens, starting with a letter.")
    if args.plan:
        plan(args)
        return
    settings = load_settings(args.env_file)
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
    existing_domain, existing_certificate = bound_domain(app_details(args.resource_group, args.name))
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
    # Before the app starts, so its first Graph token already carries every role.
    progress.step(f"Giving cloudshift inventory its {len(READ_PERMISSIONS)} read-only permissions", "under 1 min")
    consented = permissions_ok = False
    added = []
    try:
        added = ensure_read_permissions(settings["GRAPH_CLIENT_ID"])
        permissions_ok = True
        print("  added: " + ", ".join(added) if added else "  all permissions already requested")
    except SetupError:
        print("  could not update the app registration with this account; add them in the portal (below)")
    if args.grant_consent:
        try:
            granted = grant_read_permissions(settings["GRAPH_CLIENT_ID"])
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
    progress.step("Adding the hosted sign-in address to cloudshift operators")
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
    if not consented:
        lead = "New permissions need" if added or not permissions_ok else "If you have not already, grant"
        print(f"{lead} admin consent: Entra → App registrations → cloudshift inventory → API permissions")
        print("  → Grant admin consent, then restart the app (Container App → Revisions → Restart).")
        print("  Or rerun this command with --grant-consent as a Global or Privileged Role Administrator.")
    if user_admin_enabled(settings):
        print("User creation is on, using the separate 'cloudshift user admin' registration.")
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
