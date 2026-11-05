#!/usr/bin/env python3
"""Rebuild the private settings file of an existing AIO install from Azure (macOS, Linux, Cloud Shell or Windows).

Use it when .env.entra.generated was lost, for example when Cloud Shell was reset, so that install.sh
and deploy-azure.py can update the install again. Reads app IDs and settings from the Container App
and the three secrets from its Key Vault. Never prints credential values. Python standard library only.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import sys
import tempfile

spec = importlib.util.spec_from_file_location("deployment", Path(__file__).with_name("deploy-azure.py"))
deployment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployment)
SetupError, cli = deployment.SetupError, deployment.cli

# Plain settings copied from the Container App, in the order register-entra.py writes them.
PLAIN = ("NEXTAUTH_URL", "ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "GRAPH_CLIENT_ID", "CLOUDSHIFT_OPERATOR_IDS",
         "CLOUDSHIFT_TENANTS_JSON", deployment.OPERATOR_GROUP, deployment.USER_ADMIN_FLAG, "USERADMIN_CLIENT_ID")


def quote(value):
    text = str(value)
    if any(char in text for char in ("'", "\n", "\r")):
        raise SetupError("Unexpected characters in a stored value; nothing was written or printed.")
    return "'" + text.replace("$", "\\$") + "'"


def app_settings(app):
    """Plain (non-secret) environment values of the AIO container."""
    containers = (app or {}).get("properties", {}).get("template", {}).get("containers") or []
    if not containers:
        raise SetupError("No AIO container found. Check --resource-group and --name.")
    return {item["name"]: item["value"] for item in containers[0].get("env", [])
            if isinstance(item, dict) and "name" in item and "value" in item}


def vault_name(group):
    names = [name for name in cli(["keyvault", "list", "--resource-group", group, "--query", "[].name"]) or []
             if isinstance(name, str) and name.startswith("kv-")]
    if len(names) != 1:
        raise SetupError(f"Expected one AIO Key Vault in {group}; found {len(names)}.")
    return names[0]


def settings_text(plain, secrets):
    values = {"CLOUDSHIFT_DEMO_MODE": "false"}
    values.update({key: plain[key] for key in PLAIN if plain.get(key)})
    values.update(secrets)
    lines = ["# Private generated local configuration, rebuilt from Azure. Never commit or share."]
    lines += [f"{key}={quote(value)}" for key, value in values.items()]
    return "\n".join(lines) + "\n"


def write_private(path, text):
    if path.exists() or path.is_symlink():
        raise SetupError(f"{path.name} already exists; nothing was changed.")
    fd, temporary = tempfile.mkstemp(prefix=".env.recover-", dir=path.parent)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        deployment.load_settings(Path(temporary))  # same checks the deploy applies
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resource-group", default="cloudshift-rg")
    parser.add_argument("--name", default="cloudshift", help="Container App name")
    parser.add_argument("--out", type=Path, default=deployment.DEFAULT_ENV, help="Settings file to create")
    args = parser.parse_args()
    if args.out.exists() or args.out.is_symlink():
        raise SetupError(f"{args.out.name} already exists; nothing to recover.")
    progress = deployment.Progress(3)
    progress.step("Reading AIO's settings from the Container App")
    plain = app_settings(deployment.app_details(args.resource_group, args.name))
    missing = [key for key in ("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "GRAPH_CLIENT_ID") if not plain.get(key)]
    if missing:
        raise SetupError("The Container App is missing: " + ", ".join(missing))
    account = cli(["account", "show"])
    if deployment.identifier(account.get("tenantId")) != deployment.identifier(plain["ENTRA_TENANT_ID"]):
        raise SetupError("Azure CLI is signed in to a different tenant than this AIO install.")
    progress.step("Reading the secrets from Key Vault")
    vault = vault_name(args.resource_group)
    names = dict(deployment.SECRETS)
    if plain.get(deployment.USER_ADMIN_FLAG) == "true":
        names.update(deployment.USER_ADMIN_SECRETS)
    secrets = {}
    try:
        for secret, key in names.items():
            value = cli(["keyvault", "secret", "show", "--vault-name", vault, "--name", secret, "--query", "value"])
            if not isinstance(value, str) or not value:
                raise SetupError("Key Vault returned an empty secret.")
            secrets[key] = value
    except SetupError:
        raise SetupError(f"Could not read the secrets from Key Vault {vault}. Run this as the account that "
                         "installed AIO, or give your account 'Key Vault Secrets User' on that vault.") from None
    progress.step("Writing " + args.out.name + " (private)")
    write_private(args.out, settings_text(plain, secrets))
    progress.finish()
    print(f"Rebuilt {args.out.name}. Updates work again: bash install.sh (Cloud Shell) or deploy-azure.py.")


if __name__ == "__main__":
    try:
        main()
    except (SetupError, OSError, KeyError, TypeError, ValueError):
        error = sys.exc_info()[1]
        print("Recovery stopped: " + (str(error) if isinstance(error, SetupError) else
              "Local failure; configuration values and response details were not logged."), file=sys.stderr)
        sys.exit(1)
