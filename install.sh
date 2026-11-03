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
echo "AIO reads users, devices, licences, Conditional Access, Intune, Defender incidents and Microsoft 365"
echo "health through Microsoft Graph, with 10 read-only permissions. It cannot change anything."
read -rp "Grant admin consent for that now? Needs Global Administrator or Privileged Role Administrator. [Y/n] " answer
[[ "$answer" =~ ^[Nn]$ ]] || consent=(--grant-consent)

echo
echo "Step A: app registrations"
if [[ -f .env.entra.generated ]]; then
  echo "  Reusing the registrations created by an earlier run."
else
  python3 scripts/register-entra.py --tenant-id "$tenant" --tenant-name "$company" --for-hosting
fi

echo
echo "Step B: hosting (you will be asked for the image pull token you were given)"
python3 scripts/deploy-azure.py --env-file .env.entra.generated --image "$IMAGE" --location "$region" "${consent[@]}"
