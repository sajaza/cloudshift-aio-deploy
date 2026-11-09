#!/usr/bin/env bash
# cloudshift AIO installer for Azure Cloud Shell (Bash).
# Creates the two Entra app registrations, then hosts AIO on Azure Container Apps
# from the published image. Secrets go to private files and Key Vault, never to the screen.
set -euo pipefail
cd "$(dirname "$0")"
IMAGE="${CLOUDSHIFT_IMAGE:-ghcr.io/sajaza/cloudshift-aio:latest}"

for tool in az python3; do
  command -v "$tool" >/dev/null || { echo "Run this in Azure Cloud Shell (Bash): https://shell.azure.com"; exit 1; }
done

tenant=$(az account show --query tenantId -o tsv)
tenant_name=$(az account show --query tenantDisplayName -o tsv 2>/dev/null || true)
subscription=$(az account show --query name -o tsv)

echo
echo "cloudshift AIO installer"
echo "  Tenant:       ${tenant_name:-unknown} ($tenant)"
echo "  Subscription: $subscription"
echo "To use a different subscription, answer n and run: az account set --subscription NAME"
read -rp "Install AIO here? [y/N] " answer
[[ "$answer" =~ ^[Yy]$ ]] || { echo "Nothing was changed."; exit 0; }

read -rp "Company name shown in AIO [${tenant_name:-cloudshift}]: " company
company=${company:-${tenant_name:-cloudshift}}

read -rp "Azure region [eastus]: " region
region=${region:-eastus}
[[ "$region" =~ ^[a-z0-9]+$ ]] || { echo "Region must look like eastus or uksouth."; exit 1; }

consent=()
# Opt-in: CLOUDSHIFT_FEDERATION=true bash install.sh hosts AIO without an inventory client secret
# (workload identity federation). An install that already uses it keeps it on every rerun.
federation=()
[[ "${CLOUDSHIFT_FEDERATION:-false}" == "true" ]] && federation=(--federation)
echo "AIO reads users, groups, devices, sign-ins, roles, apps, Intune, Defender, Secure Score, SharePoint,"
echo "usage reports, Microsoft 365 health and Exchange Online settings, with 35 read-only permissions (34 Microsoft Graph,"
echo "1 Exchange Online). It cannot change anything; Exchange also needs a View-Only role that grant-permissions.py explains."
read -rp "Grant admin consent for that now? Needs Global Administrator or Privileged Role Administrator. [Y/n] " answer
[[ "$answer" =~ ^[Nn]$ ]] || consent=(--grant-consent)

group=""
echo "Optional: let everyone in an Entra security group sign in, as well as you."
read -rp "Entra group whose members may use AIO (name or object ID, Enter to skip): " group_answer
if [[ -n "$group_answer" ]]; then
  group=$(az ad group show --group "$group_answer" --query id -o tsv --only-show-errors 2>/dev/null || true)
  [[ "$group" =~ ^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$ ]] || {
    echo "No single Entra group matches that name or ID. Nothing was changed."; exit 1; }
  echo "  Using group $group. Members (including nested groups) may sign in."
fi

echo
echo "Step A: app registrations"
if [[ -f .env.entra.generated ]]; then
  echo "  Reusing the registrations created by an earlier run."
else
  python3 scripts/register-entra.py --tenant-id "$tenant" --tenant-name "$company" --for-hosting
fi
if [[ -n "$group" ]]; then
  python3 scripts/register-entra.py --set-operator-group "$group" --env-file .env.entra.generated
fi

echo
echo "Step B: hosting (you will be asked for the image pull token you were given)"
python3 scripts/deploy-azure.py --env-file .env.entra.generated --image "$IMAGE" --location "$region" \
  "${consent[@]}" "${federation[@]}"

echo
echo "Optional: to build and view Azure Virtual Desktop from AIO, run once per tenant"
echo "  python3 scripts/enable-avd.py --env-file .env.entra.generated, then bash install.sh again (see docs/AVD.md)."
