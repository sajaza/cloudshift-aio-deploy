#!/usr/bin/env python3
"""Turn on AIO's optional "Add user" feature (macOS, Linux or Windows).

Add user writes AS THE SIGNED-IN OPERATOR: AIO asks Microsoft for a delegated Graph token for that
person, so Entra limits each write to their own roles (for example User Administrator), applies MFA
and Conditional Access, and its audit log names them. No app holds a standing write permission.

This script adds the DELEGATED Microsoft Graph permission User.ReadWrite.All to the existing
"cloudshift operators" sign-in registration, grants tenant-wide admin consent for exactly that
delegated permission (merged into any existing consent without removing other scopes), and sets
CLOUDSHIFT_ENABLE_USER_ADMIN='true' in your private configuration file. It creates no app and no
secret. Rerun your usual deploy command afterwards. Python standard library only.
Run --plan to see what happens, or --disable to turn the feature off and withdraw the consent.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from urllib.parse import quote as url_quote

spec = importlib.util.spec_from_file_location("deployment", Path(__file__).with_name("deploy-azure.py"))
deployment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployment)
SetupError, cli, identifier = deployment.SetupError, deployment.cli, deployment.identifier

# The one delegated Graph permission Add user needs. Never an application permission.
SCOPE = "User.ReadWrite.All"
PERMISSIONS = (SCOPE,)
FLAG = deployment.USER_ADMIN_FLAG
# The retired app-only registration this feature used before 2026-11-05.
LEGACY_DISPLAY_NAME = "cloudshift user admin"
LEGACY_KEYS = deployment.LEGACY_USER_ADMIN
GRANTS_URL = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
KEY = re.compile(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=")


def quote(value):
    """Single-quoted dotenv value as register-entra.py writes it; dollars escaped for Next.js."""
    text = str(value)
    if any(char in text for char in ("'", "\n", "\r")):
        raise SetupError("Unexpected configuration-value characters; values were not printed.")
    return "'" + text.replace("$", "\\$") + "'"


def updated_text(text, updates):
    """Replace KEY=… lines for the given keys and append missing ones; a None value removes the key.
    Every other line stays as is."""
    lines, seen = [], set()
    for line in text.splitlines():
        match = KEY.match(line)
        if match and match.group(1) in updates:
            key = match.group(1)
            seen.add(key)
            if updates[key] is not None:
                lines.append(key + "=" + quote(updates[key]))
        else:
            lines.append(line)
    lines += [key + "=" + quote(value) for key, value in updates.items() if key not in seen and value is not None]
    return "\n".join(lines) + "\n"


def update_env(path, updates):
    """Atomically rewrite the private configuration file with mode 0600; no copy or backup is made."""
    if path.is_symlink() or not path.is_file():
        raise SetupError(f"Refusing to write {path.name}: it is missing, linked or not a regular file.")
    text = updated_text(path.read_text(encoding="utf-8"), updates)
    deployment.parse_env(text)  # never write a file the deploy script could not read back
    fd, temporary = tempfile.mkstemp(prefix=".env.setup-", dir=path.parent)
    try:
        # mkstemp already creates the file owner-only; Windows has no fchmod and relies on profile ACLs.
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def legacy_settings(path):
    """USERADMIN_ values in the file as written, before load_settings drops them."""
    try:
        raw = deployment.parse_env(path.read_text(encoding="utf-8"))
    except (OSError, SetupError):
        return {}
    return {key: raw[key] for key in LEGACY_KEYS if raw.get(key)}


def legacy_cleanup(legacy):
    """File updates that remove the retired app's settings. load_settings has already printed how to
    delete that app; the client ID is not a secret, the old secret is never printed."""
    if not legacy:
        return {}
    print(f"Removing the old '{LEGACY_DISPLAY_NAME}' USERADMIN_ lines from the configuration file. Delete")
    print("  that registration as shown above; optionally delete its stored secret too:")
    print("    az keyvault secret delete --vault-name YOUR-VAULT --name useradmin-client-secret")
    return {key: None for key in LEGACY_KEYS}


def graph_scope_id(graph):
    """ID of the delegated (oauth2PermissionScopes) User.ReadWrite.All on Microsoft Graph."""
    matches = [s for s in graph.get("oauth2PermissionScopes", [])
               if s.get("value") == SCOPE and s.get("isEnabled", True)]
    if len(matches) != 1:
        raise SetupError("Microsoft Graph delegated permission unavailable: " + SCOPE)
    return identifier(matches[0]["id"])


def operators_app(settings):
    """The cloudshift operators sign-in registration (ENTRA_CLIENT_ID), checked before it is changed."""
    app_id = settings["ENTRA_CLIENT_ID"]
    if app_id == settings["GRAPH_CLIENT_ID"]:
        raise SetupError("ENTRA_CLIENT_ID is the inventory app. Delegated writes belong on the sign-in app.")
    app = cli(["ad", "app", "show", "--id", app_id])
    if app.get("signInAudience") != "AzureADMyOrg":
        raise SetupError("The operators sign-in app must be single-tenant (AzureADMyOrg); nothing was changed.")
    return app


def with_scope(access, scope_id, present):
    """requiredResourceAccess with the delegated scope added (present=True) or removed. Other entries,
    including any Graph application roles, are never added, removed or changed."""
    access = json.loads(json.dumps(access or []))
    graph = next((e for e in access if e.get("resourceAppId") == deployment.GRAPH_APP_ID), None)
    if graph is None:
        if not present:
            return access, False
        graph = {"resourceAppId": deployment.GRAPH_APP_ID, "resourceAccess": []}
        access.append(graph)
    items = graph.setdefault("resourceAccess", [])
    has = any(str(i.get("id")).lower() == scope_id and i.get("type") == "Scope" for i in items)
    if present and not has:
        items.append({"id": scope_id, "type": "Scope"})
        return access, True
    if not present and has:
        graph["resourceAccess"] = [i for i in items
                                   if not (str(i.get("id")).lower() == scope_id and i.get("type") == "Scope")]
        return access, True
    return access, False


def set_required_access(app_id, access):
    with tempfile.TemporaryDirectory(prefix="cloudshift-setup-") as directory:
        body = deployment.private_temp(directory, "body.json", json.dumps({"requiredResourceAccess": access}))
        cli(["rest", "--method", "PATCH",
             "--url", f"https://graph.microsoft.com/v1.0/applications(appId='{identifier(app_id)}')",
             "--headers", "Content-Type=application/json", "--body", "@" + str(body)])


def scopes_of(text):
    return [s for s in str(text or "").split() if s]


def merged_scope(text, scope=SCOPE):
    """Scope string with `scope` added once; every other scope is kept in its order."""
    current = scopes_of(text)
    if any(s.lower() == scope.lower() for s in current):
        return " ".join(current)
    return " ".join(current + [scope])


def without_scope(text, scope=SCOPE):
    return " ".join(s for s in scopes_of(text) if s.lower() != scope.lower())


def delegated_grants(client_id, graph_id):
    """oauth2PermissionGrants from the operators app to Microsoft Graph (tenant-wide and per-user)."""
    query = url_quote(f"clientId eq '{client_id}' and resourceId eq '{graph_id}'", safe="")
    found = cli(["rest", "--method", "GET", "--url", f"{GRANTS_URL}?$filter={query}"]).get("value", [])
    return [g for g in found if g.get("clientId") == client_id and g.get("resourceId") == graph_id]


def send(method, url, body=None):
    args = ["rest", "--method", method, "--url", url]
    with tempfile.TemporaryDirectory(prefix="cloudshift-setup-") as directory:
        if body is not None:
            path = deployment.private_temp(directory, "body.json", json.dumps(body))
            args += ["--headers", "Content-Type=application/json", "--body", "@" + str(path)]
        return cli(args)


def grant_tenant_consent(client_id, graph_id):
    """Tenant-wide (AllPrincipals) delegated consent that includes exactly one new scope, User.ReadWrite.All.
    Returns 'granted', 'merged' or 'already'."""
    tenant_wide = [g for g in delegated_grants(client_id, graph_id) if g.get("consentType") == "AllPrincipals"]
    if not tenant_wide:
        send("POST", GRANTS_URL, {"clientId": client_id, "consentType": "AllPrincipals",
                                  "resourceId": graph_id, "scope": SCOPE})
        return "granted"
    grant = tenant_wide[0]
    scope = merged_scope(grant.get("scope"))
    if scope == " ".join(scopes_of(grant.get("scope"))):
        return "already"
    send("PATCH", f"{GRANTS_URL}/{url_quote(str(grant.get('id')), safe='')}", {"scope": scope})
    return "merged"


def revoke_consent(client_id, graph_id):
    """Removes User.ReadWrite.All from every consent the operators app holds for Graph (tenant-wide or
    per-user), keeping all other scopes. A grant left with no scope is deleted. Returns the count changed."""
    changed = 0
    for grant in delegated_grants(client_id, graph_id):
        current = scopes_of(grant.get("scope"))
        remaining = without_scope(grant.get("scope"))
        if remaining == " ".join(current):
            continue
        url = f"{GRANTS_URL}/{url_quote(str(grant.get('id')), safe='')}"
        if remaining:
            send("PATCH", url, {"scope": remaining})
        else:
            send("DELETE", url)
        changed += 1
    return changed


def application_roles(principal, graph_id, names):
    """Graph application roles consented to the operators app. It should have none."""
    url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{principal}/appRoleAssignments"
    current = cli(["rest", "--method", "GET", "--url", url]).get("value", [])
    return sorted({names.get(str(i.get("appRoleId")).lower(), "unknown role")
                   for i in current if i.get("resourceId") == graph_id})


def check_account(settings):
    if not shutil.which("az"):
        raise SetupError("Install Microsoft's Azure CLI, then sign in with az login --tenant TENANT_ID.")
    account = cli(["account", "show"])
    if identifier(account.get("tenantId")) != settings["ENTRA_TENANT_ID"]:
        raise SetupError("Azure CLI is signed in to a different tenant than AIO. "
                         "Run az login --tenant " + settings["ENTRA_TENANT_ID"])
    return account


def plan():
    print("Check the Azure CLI is signed in to AIO's tenant (ENTRA_TENANT_ID).")
    print("On the existing 'cloudshift operators' sign-in app (ENTRA_CLIENT_ID), request exactly one DELEGATED")
    print(f"  Microsoft Graph permission, {SCOPE}. No application permission, new app or secret is created.")
    print("Grant tenant-wide admin consent for that delegated permission (oauth2PermissionGrant, AllPrincipals),")
    print("  merged into any existing consent for the app without removing other scopes.")
    print(f"Save {FLAG}='true' to the private configuration file (mode 0600) and remove any old USERADMIN_ lines.")
    print("Then rerun your usual deploy command to switch the feature on.")
    print("Operators then create users as themselves: AIO asks Microsoft to confirm (step-up) before the first")
    print("  write, and each operator needs the User Administrator role (or higher) in Entra.")
    print(f"--disable sets {FLAG}='false', removes {SCOPE} from the app's consent and requested permissions,")
    print("  and keeps every other scope.")


def disable(path, settings, legacy):
    update_env(path, {FLAG: "false", **legacy_cleanup(legacy)})
    print(f"User creation is now off in {path.name}.")
    print("Rerun your usual deploy command, for example: python3 scripts/deploy-azure.py --env-file " + str(path))
    print(f"Withdrawing the delegated {SCOPE} consent from cloudshift operators…")
    try:
        check_account(settings)
        graph = cli(["ad", "sp", "show", "--id", deployment.GRAPH_APP_ID])
        graph_id, scope_id = identifier(graph.get("id")), graph_scope_id(graph)
        app = operators_app(settings)
        client_id = deployment.service_principal(settings["ENTRA_CLIENT_ID"])
        changed = revoke_consent(client_id, graph_id)
        access, edited = with_scope(app.get("requiredResourceAccess"), scope_id, present=False)
        if edited:
            set_required_access(settings["ENTRA_CLIENT_ID"], access)
    except SetupError as error:
        raise SetupError(f"{error} The feature is already off in {path.name}. Remove the consent by hand: "
                         "Entra → Enterprise applications → cloudshift operators → Permissions → "
                         f"{SCOPE} → Revoke, as a Global or Privileged Role Administrator.") from None
    print(f"  removed from {changed} consent(s)" if changed else "  no consent included it")
    print("Existing signed-in operators lose write access at sign-out or within 8 hours; restart the app")
    print("  (Container App → Revisions → Restart) to drop it at once.")


def enable(path, settings, legacy):
    progress = deployment.Progress(5)
    progress.step("Checking your Azure sign-in")
    account = check_account(settings)
    print("Signed in as " + str(account.get("user", {}).get("name", "unknown")))
    progress.step("Checking the cloudshift operators sign-in app")
    app = operators_app(settings)
    graph = cli(["ad", "sp", "show", "--id", deployment.GRAPH_APP_ID])
    graph_id, scope_id = identifier(graph.get("id")), graph_scope_id(graph)
    client_id = deployment.service_principal(settings["ENTRA_CLIENT_ID"])
    print("  client ID " + settings["ENTRA_CLIENT_ID"])
    progress.step(f"Requesting delegated {SCOPE} (the only permission it needs)")
    access, edited = with_scope(app.get("requiredResourceAccess"), scope_id, present=True)
    if edited:
        set_required_access(settings["ENTRA_CLIENT_ID"], access)
    print("  added" if edited else "  already requested")
    progress.step(f"Granting tenant-wide admin consent for delegated {SCOPE}")
    try:
        outcome = grant_tenant_consent(client_id, graph_id)
    except SetupError:
        raise SetupError("Admin consent failed. Sign in as a Global Administrator or Privileged Role "
                         "Administrator (az login --tenant " + settings["ENTRA_TENANT_ID"] + ") and rerun, "
                         "or grant it in Entra → App registrations → cloudshift operators → API permissions → "
                         "Grant admin consent.") from None
    print({"granted": "  granted", "merged": "  added to the existing consent", "already": "  already granted"}
          [outcome])
    names = {str(r.get("id")).lower(): r.get("value") for r in graph.get("appRoles", [])}
    roles = application_roles(client_id, graph_id, names)
    if roles:
        print("  warning: cloudshift operators also has application permissions consented: " + ", ".join(roles)
              + ". The sign-in app needs none; remove them in Entra → Enterprise applications → "
              "cloudshift operators → Permissions.")
    progress.step("Saving the setting to your private configuration file")
    update_env(path, {FLAG: "true", **legacy_cleanup(legacy)})
    progress.finish()
    print()
    print(f"User creation is ready in {path.name}. Now rerun your usual deploy command, for example:")
    print("  python3 scripts/deploy-azure.py --env-file " + str(path))
    print("Operators create users as themselves. Each needs the User Administrator role (or higher) in Entra;")
    print("Microsoft refuses the write otherwise. AIO asks them to confirm with Microsoft before the first write.")
    print("Turn it off with --disable.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=deployment.DEFAULT_ENV, help="Live configuration file")
    parser.add_argument("--disable", action="store_true",
                        help="Turn user creation off and withdraw the delegated consent")
    parser.add_argument("--plan", action="store_true", help="Show what happens without Azure access or changes")
    args = parser.parse_args()
    if args.plan:
        plan()
        return
    legacy = legacy_settings(args.env_file)
    settings = deployment.load_settings(args.env_file, check_user_admin=False)
    if args.disable:
        disable(args.env_file, settings, legacy)
    else:
        enable(args.env_file, settings, legacy)


if __name__ == "__main__":
    try:
        main()
    except (SetupError, OSError, KeyError, TypeError, ValueError):
        # Catch unexpected failures without printing locals, configuration values, or tracebacks.
        error = sys.exc_info()[1]
        print("User admin setup stopped: " + (str(error) if isinstance(error, SetupError) else
              "Local failure; configuration values and response details were not logged."), file=sys.stderr)
        sys.exit(1)
