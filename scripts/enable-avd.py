#!/usr/bin/env python3
"""Turn on AIO's optional Azure Virtual Desktop area (macOS, Linux or Windows).

The AVD area builds and views Azure Virtual Desktop AS THE SIGNED-IN OPERATOR: AIO asks Microsoft for a
delegated Azure Resource Manager token for that person, so Azure limits each call to their own Azure
roles (RBAC), applies MFA and Conditional Access, and its activity log names them. AIO itself gets no
Azure role on any subscription.

This script makes sure the Microsoft "Windows Azure Service Management API" exists as an enterprise
application in your tenant, adds its DELEGATED permission user_impersonation to the existing
"cloudshift operators" sign-in registration, grants tenant-wide admin consent for exactly that
delegated permission (merged into any existing consent without removing other scopes), and sets
CLOUDSHIFT_ENABLE_AVD='true' in your private configuration file. It creates no app, secret or Azure
role assignment. Rerun your usual deploy command afterwards. Python standard library only.
Run --plan to see what happens, or --disable to turn the feature off and withdraw the consent.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
from urllib.parse import quote as url_quote

# Shares the configuration-file and scope-string helpers of enable-user-admin.py, and through it the
# same deploy-azure.py module instance (so SetupError and cli are one and the same).
spec = importlib.util.spec_from_file_location("useradmin", Path(__file__).with_name("enable-user-admin.py"))
useradmin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(useradmin)
deployment = useradmin.deployment
SetupError, cli, identifier = deployment.SetupError, deployment.cli, deployment.identifier
update_env, merged_scope, without_scope, scopes_of = (
    useradmin.update_env, useradmin.merged_scope, useradmin.without_scope, useradmin.scopes_of)

# Microsoft's first-party "Windows Azure Service Management API" (Azure Resource Manager) application.
# Same app ID in every Entra tenant of the Azure public cloud.
ASM_APP_ID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
ASM_NAME = "Windows Azure Service Management API"
# The one delegated permission the AVD area needs. Its ID is read from the tenant's service principal
# (oauth2PermissionScopes) at run time; Microsoft's published ID is 41094075-9dad-400e-a0bd-54e686782033.
SCOPE = "user_impersonation"
PERMISSIONS = (SCOPE,)
FLAG = deployment.AVD_FLAG
GRANTS_URL = useradmin.GRANTS_URL
RBAC_NOTE = ("AIO grants no Azure roles itself. Each operator who builds AVD needs Azure roles on the target\n"
             "  subscription or resource group: Contributor plus User Access Administrator, or Owner.\n"
             "  Viewing needs at least Desktop Virtualization Reader (or Reader).")


def check_account(settings):
    if not shutil.which("az"):
        raise SetupError("Install Microsoft's Azure CLI, then sign in with az login --tenant TENANT_ID.")
    account = cli(["account", "show"])
    if identifier(account.get("tenantId")) != settings["ENTRA_TENANT_ID"]:
        raise SetupError("Azure CLI is signed in to a different tenant than AIO. "
                         "Run az login --tenant " + settings["ENTRA_TENANT_ID"])
    return account


def operators_app(settings):
    """The cloudshift operators sign-in registration (ENTRA_CLIENT_ID), checked before it is changed."""
    app_id = settings["ENTRA_CLIENT_ID"]
    if app_id == settings["GRAPH_CLIENT_ID"]:
        raise SetupError("ENTRA_CLIENT_ID is the inventory app. Delegated Azure access belongs on the sign-in app.")
    app = cli(["ad", "app", "show", "--id", app_id])
    if app.get("signInAudience") != "AzureADMyOrg":
        raise SetupError("The operators sign-in app must be single-tenant (AzureADMyOrg); nothing was changed.")
    return app


def find_asm():
    """Object ID of the Azure Service Management enterprise application in this tenant, or None."""
    found = cli(["ad", "sp", "list", "--filter", f"appId eq '{ASM_APP_ID}'"]) or []
    found = [sp for sp in found if str(sp.get("appId", ASM_APP_ID)).lower() == ASM_APP_ID]
    return identifier(found[0]["id"]) if found else None


def ensure_asm():
    """Returns (object ID, created). Most tenants already have it (the Azure portal and CLI use it);
    creating it only adds Microsoft's own app to the tenant and grants nothing."""
    existing = find_asm()
    if existing:
        return existing, False
    print(f"  '{ASM_NAME}' is not in this tenant yet; adding Microsoft's enterprise application for it.")
    print("  This creates no permission or role. It is the app Azure Resource Manager tokens are issued for.")
    try:
        created = cli(["ad", "sp", "create", "--id", ASM_APP_ID])
    except SetupError:
        raise SetupError(f"Could not add '{ASM_NAME}' to the tenant. Sign in as an Application Administrator, "
                         "Cloud Application Administrator or Global Administrator and rerun.") from None
    return identifier(created.get("id")), True


def asm_scope_id(asm_id):
    """ID of the delegated (oauth2PermissionScopes) user_impersonation on Azure Service Management."""
    asm = cli(["ad", "sp", "show", "--id", asm_id])
    if str(asm.get("appId", ASM_APP_ID)).lower() != ASM_APP_ID:
        raise SetupError(f"The service principal found is not '{ASM_NAME}'; nothing was changed.")
    matches = [s for s in asm.get("oauth2PermissionScopes", [])
               if s.get("value") == SCOPE and s.get("isEnabled", True)]
    if len(matches) != 1:
        raise SetupError(f"{ASM_NAME} delegated permission unavailable: {SCOPE}")
    return identifier(matches[0]["id"])


def with_scope(access, scope_id, present):
    """requiredResourceAccess with the delegated scope on Azure Service Management added (present=True) or
    removed. Every other entry is kept as is; an Azure Service Management entry left empty is dropped."""
    access = json.loads(json.dumps(access or []))
    entry = next((e for e in access if str(e.get("resourceAppId")).lower() == ASM_APP_ID), None)
    if entry is None:
        if not present:
            return access, False
        entry = {"resourceAppId": ASM_APP_ID, "resourceAccess": []}
        access.append(entry)
    items = entry.setdefault("resourceAccess", [])

    def ours(item):
        return str(item.get("id")).lower() == scope_id and item.get("type") == "Scope"

    has = any(ours(i) for i in items)
    if present and not has:
        items.append({"id": scope_id, "type": "Scope"})
        return access, True
    if not present and has:
        entry["resourceAccess"] = [i for i in items if not ours(i)]
        if not entry["resourceAccess"]:
            access.remove(entry)
        return access, True
    return access, False


def set_required_access(app_id, access):
    with tempfile.TemporaryDirectory(prefix="cloudshift-setup-") as directory:
        body = deployment.private_temp(directory, "body.json", json.dumps({"requiredResourceAccess": access}))
        cli(["rest", "--method", "PATCH",
             "--url", f"https://graph.microsoft.com/v1.0/applications(appId='{identifier(app_id)}')",
             "--headers", "Content-Type=application/json", "--body", "@" + str(body)])


def send(method, url, body=None):
    args = ["rest", "--method", method, "--url", url]
    with tempfile.TemporaryDirectory(prefix="cloudshift-setup-") as directory:
        if body is not None:
            path = deployment.private_temp(directory, "body.json", json.dumps(body))
            args += ["--headers", "Content-Type=application/json", "--body", "@" + str(path)]
        return cli(args)


def delegated_grants(client_id, resource_id):
    """oauth2PermissionGrants from the operators app to Azure Service Management (tenant-wide and per-user)."""
    query = url_quote(f"clientId eq '{client_id}' and resourceId eq '{resource_id}'", safe="")
    found = cli(["rest", "--method", "GET", "--url", f"{GRANTS_URL}?$filter={query}"]).get("value", [])
    return [g for g in found if g.get("clientId") == client_id and g.get("resourceId") == resource_id]


def grant_tenant_consent(client_id, resource_id):
    """Tenant-wide (AllPrincipals) delegated consent that adds exactly one scope, user_impersonation.
    Returns 'granted', 'merged' or 'already'."""
    tenant_wide = [g for g in delegated_grants(client_id, resource_id) if g.get("consentType") == "AllPrincipals"]
    if not tenant_wide:
        send("POST", GRANTS_URL, {"clientId": client_id, "consentType": "AllPrincipals",
                                  "resourceId": resource_id, "scope": SCOPE})
        return "granted"
    grant = tenant_wide[0]
    scope = merged_scope(grant.get("scope"), SCOPE)
    if scope == " ".join(scopes_of(grant.get("scope"))):
        return "already"
    send("PATCH", f"{GRANTS_URL}/{url_quote(str(grant.get('id')), safe='')}", {"scope": scope})
    return "merged"


def revoke_consent(client_id, resource_id):
    """Removes user_impersonation from every consent the operators app holds for Azure Service Management
    (tenant-wide or per-user), keeping all other scopes. A grant left empty is deleted. Returns the count."""
    changed = 0
    for grant in delegated_grants(client_id, resource_id):
        remaining = without_scope(grant.get("scope"), SCOPE)
        if remaining == " ".join(scopes_of(grant.get("scope"))):
            continue
        url = f"{GRANTS_URL}/{url_quote(str(grant.get('id')), safe='')}"
        if remaining:
            send("PATCH", url, {"scope": remaining})
        else:
            send("DELETE", url)
        changed += 1
    return changed


def plan():
    print("Check the Azure CLI is signed in to AIO's tenant (ENTRA_TENANT_ID).")
    print(f"Make sure Microsoft's '{ASM_NAME}' ({ASM_APP_ID})")
    print("  exists as an enterprise application in the tenant; add it with az ad sp create if missing")
    print("  (that grants nothing on its own).")
    print("On the existing 'cloudshift operators' sign-in app (ENTRA_CLIENT_ID), request exactly one DELEGATED")
    print(f"  permission, Azure Service Management {SCOPE}. No application permission, app, secret or")
    print("  Azure role assignment is created.")
    print("Grant tenant-wide admin consent for that delegated permission (oauth2PermissionGrant, AllPrincipals),")
    print("  merged into any existing consent for the app without removing other scopes.")
    print(f"Save {FLAG}='true' to the private configuration file (mode 0600).")
    print("Then rerun your usual deploy command to switch the feature on.")
    print(RBAC_NOTE)
    print(f"--disable sets {FLAG}='false', removes {SCOPE} from the app's consent and requested")
    print("  permissions, and keeps every other scope.")


def disable(path, settings):
    update_env(path, {FLAG: "false"})
    print(f"Azure Virtual Desktop is now off in {path.name}.")
    print("Rerun your usual deploy command, for example: python3 scripts/deploy-azure.py --env-file " + str(path))
    print(f"Withdrawing the delegated Azure Service Management {SCOPE} consent from cloudshift operators…")
    changed = 0
    try:
        check_account(settings)
        app = operators_app(settings)
        asm_id = find_asm()
        if asm_id:
            scope_id = asm_scope_id(asm_id)
            client_id = deployment.service_principal(settings["ENTRA_CLIENT_ID"])
            changed = revoke_consent(client_id, asm_id)
            access, edited = with_scope(app.get("requiredResourceAccess"), scope_id, present=False)
            if edited:
                set_required_access(settings["ENTRA_CLIENT_ID"], access)
    except SetupError as error:
        raise SetupError(f"{error} The feature is already off in {path.name}. Remove the consent by hand: "
                         "Entra → Enterprise applications → cloudshift operators → Permissions → "
                         f"Azure Service Management {SCOPE} → Revoke, as a Global or Privileged Role "
                         "Administrator.") from None
    print(f"  removed from {changed} consent(s)" if changed else "  no consent included it")
    print("Operators' existing Azure tokens expire within about an hour; restart the app")
    print("  (Container App → Revisions → Restart) to drop them at once. Azure roles you gave operators stay;")
    print("  remove them in the Azure portal if they are no longer needed.")


def enable(path, settings):
    progress = deployment.Progress(5)
    progress.step("Checking your Azure sign-in")
    account = check_account(settings)
    print("Signed in as " + str(account.get("user", {}).get("name", "unknown")))
    progress.step("Checking the cloudshift operators sign-in app and Azure Service Management")
    app = operators_app(settings)
    asm_id, created = ensure_asm()
    scope_id = asm_scope_id(asm_id)
    client_id = deployment.service_principal(settings["ENTRA_CLIENT_ID"])
    print("  client ID " + settings["ENTRA_CLIENT_ID"])
    print(f"  '{ASM_NAME}' " + ("added to the tenant" if created else "already in the tenant"))
    progress.step(f"Requesting delegated Azure Service Management {SCOPE} (the only permission it needs)")
    access, edited = with_scope(app.get("requiredResourceAccess"), scope_id, present=True)
    if edited:
        set_required_access(settings["ENTRA_CLIENT_ID"], access)
    print("  added" if edited else "  already requested")
    progress.step(f"Granting tenant-wide admin consent for delegated {SCOPE}")
    try:
        outcome = grant_tenant_consent(client_id, asm_id)
    except SetupError:
        raise SetupError("Admin consent failed. Sign in as a Global Administrator or Privileged Role "
                         "Administrator (az login --tenant " + settings["ENTRA_TENANT_ID"] + ") and rerun, "
                         "or grant it in Entra → App registrations → cloudshift operators → API permissions → "
                         "Grant admin consent.") from None
    print({"granted": "  granted", "merged": "  added to the existing consent", "already": "  already granted"}
          [outcome])
    progress.step("Saving the setting to your private configuration file")
    update_env(path, {FLAG: "true"})
    progress.finish()
    print()
    print(f"Azure Virtual Desktop is ready in {path.name}. Now rerun your usual deploy command, for example:")
    print("  python3 scripts/deploy-azure.py --env-file " + str(path))
    print("Operators build and view AVD as themselves; Azure refuses anything their own roles do not allow.")
    print(RBAC_NOTE)
    print("Deployments create billable Azure resources in the subscription the operator chooses.")
    print("Turn it off with --disable. See docs/AVD.md.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=deployment.DEFAULT_ENV, help="Live configuration file")
    parser.add_argument("--disable", action="store_true",
                        help="Turn the Azure Virtual Desktop area off and withdraw the delegated consent")
    parser.add_argument("--plan", action="store_true", help="Show what happens without Azure access or changes")
    args = parser.parse_args()
    if args.plan:
        plan()
        return
    settings = deployment.load_settings(args.env_file, check_avd=False)
    if args.disable:
        disable(args.env_file, settings)
    else:
        enable(args.env_file, settings)


if __name__ == "__main__":
    try:
        main()
    except (SetupError, OSError, KeyError, TypeError, ValueError):
        # Catch unexpected failures without printing locals, configuration values, or tracebacks.
        error = sys.exc_info()[1]
        print("Azure Virtual Desktop setup stopped: " + (str(error) if isinstance(error, SetupError) else
              "Local failure; configuration values and response details were not logged."), file=sys.stderr)
        sys.exit(1)
