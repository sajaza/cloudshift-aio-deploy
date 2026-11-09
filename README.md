# Install cloudshift AIO from your browser

_Installer kit for cloudshift AIO. It contains only the install scripts and template, copied from the private application repository: no application code and no secrets._

For the IT person installing AIO into their organisation's Microsoft tenant. You need nothing installed on your computer: everything runs in **Azure Cloud Shell**, a command window inside the Azure portal.

It takes about 15 minutes, most of it waiting while a progress bar shows each step.

## You need

- An account in the tenant that is **Owner** of an Azure subscription (to create the hosting resources) and can create app registrations.
- For the optional one-click consent: **Global Administrator** or **Privileged Role Administrator**. Without it, an admin can grant consent later in the portal.
- The **image pull token** you were sent (a code starting `ghp_`). Treat it like a password.

## Install

1. Open **https://shell.azure.com** and sign in with that account. If asked, choose **Bash** and accept the storage setup.
2. Paste this line and press Enter:

   ```sh
   git clone https://github.com/sajaza/cloudshift-aio-deploy.git && bash cloudshift-aio-deploy/install.sh
   ```

3. Answer the questions:

   | Question             | What to enter                                                       |
   | -------------------- | ------------------------------------------------------------------- |
   | Install AIO here?    | `y` if the tenant and subscription shown are right                  |
   | Company name         | Press Enter to accept, or type the name to show in AIO              |
   | Azure region         | Press Enter for `eastus`, or e.g. `uksouth`, `westeurope`           |
   | Grant admin consent? | Press Enter (yes) if you are a Global/Privileged Role Administrator |
   | Entra group          | Press Enter to skip, or a group name or object ID (see below)       |
   | Image pull token     | Paste the `ghp_…` token (it stays hidden) and press Enter           |
   | Custom web address   | Press Enter for the generic address, or type your own (see below)   |

4. Watch the steps complete. The last lines show your AIO address, such as `https://cloudshift.<random>.eastus.azurecontainerapps.io`.
5. Open that address and sign in. The account that ran the installer is the approved AIO operator.

## What it creates

- Two app registrations in Entra: **cloudshift operators** (sign-in only) and **cloudshift inventory** (23 read-only Microsoft Graph permissions: users, groups, devices, licences, Conditional Access, sign-in and audit logs, identity risk, directory roles, applications and consent requests, Intune devices, apps, policies and Autopilot, Defender incidents and alerts, Secure Score, SharePoint sites, Microsoft 365 usage reports, organisation, domains and service health). They can only read. Exchange Online, Teams and other workloads are not part of this consent: Exchange data today comes only from an optional export you run and import yourself, and any live access to them would come later as a separate, opt-in step with its own consent.
- A resource group **cloudshift-rg** with the AIO container, a private container registry, a Key Vault holding the secrets, a managed identity and a log workspace.

Secrets are never shown on screen. They live in Key Vault and in a private file in your Cloud Shell storage (`cloudshift-aio-deploy/.env.entra.generated`), which an install retry reuses; anyone who can read your Cloud Shell storage account can read it, so keep that storage account private. `.env.registration-state.json` next to it keeps the app IDs. Client secrets expire after 180 days. To host without the inventory app's client secret, start the installer with `CLOUDSHIFT_FEDERATION=true bash install.sh` (see [No secrets](AZURE-HOSTING.md#no-secrets-workload-identity-federation)).

## Limit AIO to a group (optional)

To let a team use AIO, and lock people out again by removing them from a group:

1. In **entra.microsoft.com → Groups → New group**, create a **Security** group such as `AIO operators`. Add **yourself first**, then the others.
2. **Enterprise applications → cloudshift operators → Properties → Assignment required? → Yes → Save**, then **Users and groups → Add user/group** → the group → **Assign**. (Needs Entra ID P1 or P2; members of nested groups aren't covered by this assignment, so add people to the group directly.)
3. Run the installer again and answer **Entra group whose members may use AIO** with the group's name or object ID.

Members, including nested ones, are checked at sign-in and again every 10 minutes or so. If Microsoft can't be reached, group members are refused, but the account that ran the installer still gets in. Details: [AZURE-HOSTING.md](AZURE-HOSTING.md#limit-aio-to-a-group-optional).

## Use your own web address (optional)

Instead of the generic `https://cloudshift.<random>.<region>.azurecontainerapps.io`, AIO can live at your own address such as `aio.contoso.com`. You need access to your domain's DNS. You can choose it during the install or add it later by running the installer again.

1. When asked **Custom web address for AIO**, type the address (for example `aio.contoso.com`). Press Enter instead to keep the generic address.
2. The installer prints **two DNS records**. Add both at your DNS provider:
   - a **CNAME** record: `aio` → the generic `….azurecontainerapps.io` address shown,
   - a **TXT** record: `asuid.aio` → the code shown.
     (If your DNS provider asks for full names, use `aio.contoso.com` and `asuid.aio.contoso.com`.)
3. Wait a few minutes, then press **Enter**. If Azure can't see the records yet, it says so; wait and press Enter again. Type `skip` to finish with the generic address and add the domain later.
4. Azure issues a free certificate that renews itself. AIO switches to your address; the generic address keeps working as a backup.

Later updates keep your address automatically (press Enter at the question). To go back to the generic address, type `generic`. It must be a subdomain like `aio.contoso.com`; a bare domain like `contoso.com` can't be used.

## Install a specific version (optional)

The line above installs the newest published AIO (`latest`), and every rerun updates to the newest again. To control when AIO changes, ask for a version tag (a long commit ID) and install or rerun with it:

```sh
CLOUDSHIFT_IMAGE=ghcr.io/sajaza/cloudshift-aio:<version> bash cloudshift-aio-deploy/install.sh
```

## If something goes wrong

- **"Could not copy the cloudshift image"**: the token was mistyped or has expired. Ask for a new one and paste the same line again; finished steps are reused.
- **"An existing 'cloudshift operators' registration was found"**: a previous attempt ran in a Cloud Shell session whose files are gone. Delete the two registrations in Entra (or ask your contact) and try again.
- **Admin consent could not be granted**: Entra → App registrations → cloudshift inventory → API permissions → **Grant admin consent**.
- **Sign-in refused**: only the person who ran the installer is approved at first. More operators are added by the cloudshift team.

## Remove AIO

In Cloud Shell: `az group delete --name cloudshift-rg`, then delete the two app registrations in Entra. Key Vault stays recoverable for 30 days.
