#!/usr/bin/env python3
"""Provision cloudshift registrations through the signed-in Azure CLI session.

Never prints credential values; does not grant admin consent or change tenant policy.
Python standard library only. Run --plan to inspect changes without Azure access.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import uuid
from urllib.parse import urlencode

from graph_permissions import GRAPH_APP_ID, READ_PERMISSIONS as PERMISSIONS

ROOT = Path(__file__).resolve().parents[1]
GRAPH = "https://graph.microsoft.com/v1.0"
STATE_PATH = ROOT / ".env.registration-state.json"
OUTPUT_PATH = ROOT / ".env.entra.generated"


class SetupError(Exception):
    pass


def identifier(value):
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise SetupError("Expected a valid tenant, application, or operator UUID.") from None


def private_write(path, text):
    """Atomic mode-0600 storage; refuse links and unexpected filesystem objects."""
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise SetupError("Refusing to write a linked or non-regular configuration file.")
    fd, temporary = tempfile.mkstemp(prefix=".env.setup-", dir=path.parent)
    try:
        # mkstemp already creates the file owner-only; Windows has no fchmod and relies on profile ACLs.
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def cli(args):
    # On Windows the CLI is az.cmd, which only runs when called by its resolved path.
    az = shutil.which("az") or "az"
    try:
        result = subprocess.run([az, *args, "--only-show-errors", "--output", "json"],
                                capture_output=True, text=True, encoding="utf-8", errors="replace",
                                timeout=120, check=False)
    except (subprocess.TimeoutExpired, OSError):
        raise SetupError("Azure CLI request failed or timed out; no response details were logged.") from None
    if result.returncode:
        # Both stdout and stderr can contain credential data. Never echo either.
        raise SetupError("Azure CLI request failed. Check login, tenant role, and the Entra portal; response details are suppressed.")
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        raise SetupError("Azure CLI returned an unexpected response; response details are suppressed.") from None


def graph(method, path, body=None):
    args = ["rest", "--method", method, "--url", GRAPH + path]
    if body is None:
        return cli(args)
    # Bodies are supplied via private files, not shell expansion or argv credentials.
    with tempfile.TemporaryDirectory(prefix="cloudshift-setup-") as directory:
        payload = Path(directory) / "body.json"
        private_write(payload, json.dumps(body))
        return cli(args + ["--headers", "Content-Type=application/json", "--body", "@" + str(payload)])


def collection(resource, expression, select):
    query = urlencode({"$filter": expression, "$select": select})
    response = graph("GET", f"/{resource}?{query}")
    if not isinstance(response.get("value"), list) or response.get("@odata.nextLink"):
        raise SetupError("Unexpected or ambiguous registration lookup; refusing to guess an application.")
    return response["value"]


def resolve_permissions(roles):
    result = []
    for name in PERMISSIONS:
        matches = [r for r in roles if r.get("value") == name and r.get("isEnabled")
                   and "Application" in r.get("allowedMemberTypes", [])]
        if len(matches) != 1:
            raise SetupError("Microsoft Graph application permission unavailable: " + name)
        result.append({"id": identifier(matches[0]["id"]), "type": "Role"})
    return result


def manifests(role_ids):
    return {
        "operators": {
            "displayName": "cloudshift operators", "signInAudience": "AzureADMyOrg",
            "web": {"redirectUris": ["http://localhost:3000/api/auth/callback/azure-ad"],
                    "implicitGrantSettings": {"enableAccessTokenIssuance": False, "enableIdTokenIssuance": False}},
            "requiredResourceAccess": [],
        },
        "inventory": {
            "displayName": "cloudshift inventory", "signInAudience": "AzureADMultipleOrgs",
            "api": {"requestedAccessTokenVersion": 2},
            "requiredResourceAccess": [{"resourceAppId": GRAPH_APP_ID, "resourceAccess": role_ids}],
        },
    }


def save_state(state):
    private_write(STATE_PATH, json.dumps(state, indent=2) + "\n")


def load_state(tenant_id, operator_id):
    if STATE_PATH.is_symlink():
        raise SetupError("Refusing a linked registration state file.")
    if not STATE_PATH.exists():
        if OUTPUT_PATH.exists() or OUTPUT_PATH.is_symlink():
            raise SetupError("Generated environment file already exists without setup state; refusing to overwrite it.")
        state = {"version": 1, "tenant_id": tenant_id, "operator_id": operator_id,
                 "session_secret": secrets.token_urlsafe(48), "apps": {}}
        save_state(state)
        return state
    # Check restrictive permissions before reading stored credentials.
    # Windows protects files in the user profile with ACLs rather than mode bits.
    if os.name != "nt" and STATE_PATH.stat().st_mode & 0o077:
        raise SetupError("State file must be private: run chmod 600 .env.registration-state.json.")
    try:
        state = json.loads(STATE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        raise SetupError("Cannot read registration state; refusing to create replacement registrations.") from None
    if state.get("version") != 1 or state.get("tenant_id") != tenant_id or state.get("operator_id") != operator_id:
        raise SetupError("Setup state belongs to a different tenant/operator or format; refusing to reuse it.")
    return state


def provision_app(key, manifest, state):
    apps = state["apps"]
    record = apps.get(key)
    if record:
        current = graph("GET", "/applications/" + identifier(record["object_id"]))
        if current.get("appId") != record["client_id"]:
            raise SetupError("Saved application no longer matches Entra; refusing to reuse it.")
    else:
        current = graph("POST", "/applications", manifest)
        record = {"object_id": identifier(current["id"]), "client_id": identifier(current["appId"])}
        apps[key] = record
        save_state(state)
    principals = collection("servicePrincipals", "appId eq '" + record["client_id"] + "'", "id,appId")
    if not principals:
        graph("POST", "/servicePrincipals", {"appId": record["client_id"]})
    elif len(principals) != 1:
        raise SetupError("Ambiguous enterprise application lookup.")
    if "secret" not in record:
        expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%SZ")
        credential = graph("POST", "/applications/" + record["object_id"] + "/addPassword",
                           {"passwordCredential": {"displayName": "cloudshift local setup", "endDateTime": expiry}})
        if not credential.get("secretText"):
            raise SetupError("Entra did not return a new credential; refusing to print response details.")
        record.update(secret=credential["secretText"], secret_key_id=identifier(credential["keyId"]), expires=expiry)
        save_state(state)
    print(manifest["displayName"] + ": ready (client ID " + record["client_id"] + ")")


def environment(state, tenant_name):
    # Escape dollar signs because Next.js expands dotenv values after quote parsing.
    def quote(value):
        text = str(value)
        if any(char in text for char in ("'", "\n", "\r")):
            raise SetupError("Unexpected environment-value characters; generated secrets were not printed.")
        return "'" + text.replace("$", "\\$") + "'"
    a, b = state["apps"]["operators"], state["apps"]["inventory"]
    values = {
        "CLOUDSHIFT_DEMO_MODE": "false", "NEXTAUTH_URL": "http://localhost:3000",
        "NEXTAUTH_SECRET": state["session_secret"], "ENTRA_TENANT_ID": state["tenant_id"],
        "ENTRA_CLIENT_ID": a["client_id"], "ENTRA_CLIENT_SECRET": a["secret"],
        "CLOUDSHIFT_OPERATOR_IDS": state["operator_id"], "GRAPH_CLIENT_ID": b["client_id"],
        "GRAPH_CLIENT_SECRET": b["secret"],
        "CLOUDSHIFT_TENANTS_JSON": json.dumps([{"id": state["tenant_id"], "name": tenant_name}]),
        "CLOUDSHIFT_GDAP_DISCOVERY": "false", "CLOUDSHIFT_PARTNER_DISCOVERY": "false",
    }
    return "# Private generated local configuration. Never commit or share.\n" + "\n".join(k + "=" + quote(v) for k, v in values.items()) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", help="Your production Entra tenant UUID")
    parser.add_argument("--tenant-name", default="cloudshift", help="Local selector display name")
    parser.add_argument("--for-hosting", action="store_true", help="Called by install.sh; skip local next steps")
    parser.add_argument("--plan", action="store_true", help="Show changes without logging in or changing Azure")
    args = parser.parse_args()
    if args.plan:
        print("Create cloudshift operators: single-tenant OIDC web app, localhost redirect, no Graph permissions.")
        print("Create cloudshift inventory: multitenant app, read-only Graph application permissions:")
        for permission in PERMISSIONS:
            print("  " + permission)
        print("Create enterprise apps and 180-day client secrets; approve only the signed-in operator locally.")
        print("Store credentials in ignored mode-0600 files; preserve .env.local. Admin consent remains a portal step.")
        return
    if not args.tenant_id:
        raise SetupError("Pass --tenant-id with your Entra tenant UUID, or use --plan.")
    tenant_id = identifier(args.tenant_id)
    if not shutil.which("az"):
        raise SetupError("Install Microsoft's Azure CLI, then sign in with az login --tenant TENANT_ID --allow-no-subscriptions.")
    if cli(["cloud", "show"]).get("name") != "AzureCloud":
        raise SetupError("This script supports the Microsoft commercial cloud only.")
    account = cli(["account", "show"])
    if identifier(account.get("tenantId")) != tenant_id:
        raise SetupError("Azure CLI is signed in to a different tenant. Sign in explicitly to the requested tenant first.")
    operator_id = identifier(graph("GET", "/me?$select=id")["id"])
    graph_principals = collection("servicePrincipals", "appId eq '" + GRAPH_APP_ID + "'", "id,appRoles")
    if len(graph_principals) != 1:
        raise SetupError("Microsoft Graph service principal not found uniquely.")
    definitions = manifests(resolve_permissions(graph_principals[0].get("appRoles", [])))
    # Preflight every unsaved display name before making any new registrations.
    state = load_state(tenant_id, operator_id)
    for key, definition in definitions.items():
        if key not in state["apps"] and collection("applications", "displayName eq '" + definition["displayName"] + "'", "id,appId"):
            raise SetupError("An existing '" + definition["displayName"] + "' registration was found without setup state. Reuse it manually; this script will not modify or delete it.")
    for key, definition in definitions.items():
        print("Preparing " + definition["displayName"] + "…")
        provision_app(key, definition, state)
    private_write(OUTPUT_PATH, environment(state, args.tenant_name))
    if args.for_hosting:
        print("App registrations ready; private configuration saved for the hosting step.")
        return
    print("Private configuration saved to .env.entra.generated; existing .env.local was preserved.")
    print("In Entra: App registrations → cloudshift inventory → API permissions → Grant admin consent.")
    print("After consent, use the generated configuration as .env.local and restart the app at http://localhost:3000.")
    print("The localhost origin must match the registered redirect. Client secrets expire after 180 days.")


if __name__ == "__main__":
    try:
        main()
    except (SetupError, OSError, KeyError, TypeError, ValueError):
        # Catch unexpected failures without printing locals, returned tokens, or tracebacks.
        error = sys.exc_info()[1]
        print("Setup stopped: " + (str(error) if isinstance(error, SetupError) else "Local setup failed; credentials and response details were not logged."), file=sys.stderr)
        sys.exit(1)
