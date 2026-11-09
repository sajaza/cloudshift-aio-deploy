// cloudshift AIO hosting on Azure Container Apps.
// Deployed twice by scripts/deploy-azure.py: first with deployApp=false (registry, vault,
// identity, environment), then with deployApp=true once secrets and the image exist.
// No secret values are template parameters; the app reads them from Key Vault by reference.

@description('Short lowercase name used for the Container App and resource names.')
@minLength(3)
@maxLength(24)
param name string = 'cloudshift'

param location string = resourceGroup().location

@description('False creates shared infrastructure only; true also creates/updates the app.')
param deployApp bool = false

@description('Entra object ID of the person running the deployment; granted Key Vault Secrets Officer to upload secrets.')
param deployerObjectId string

@allowed(['User', 'ServicePrincipal'])
param deployerPrincipalType string = 'User'

@description('Full image reference in this registry. Required when deployApp is true.')
param image string = ''

param entraTenantId string = ''
param entraClientId string = ''
param graphClientId string = ''

@description('Comma-separated approved operator object IDs.')
param operatorIds string = ''

@description('Optional Entra security group object ID; its direct and nested members may also sign in.')
param operatorGroupId string = ''

@description('JSON allowlist of approved customer tenants.')
param tenantsJson string = '[]'

@description('Optional custom hostname such as aio.contoso.com, already bound with a managed certificate.')
param customDomain string = ''

@description('Resource ID of the managed certificate for customDomain. Both must be set to use the domain.')
param customDomainCertificateId string = ''

@description('Optional Add user feature. Writes run as the signed-in operator with a delegated Microsoft Graph token, limited to their own Entra role, so no write app or secret is deployed.')
param enableUserAdmin bool = false

@description('Optional Azure Virtual Desktop area. Azure calls run as the signed-in operator with a delegated Azure Resource Manager token, limited to their own Azure roles, so AIO gets no Azure role assignment.')
param enableAvd bool = false

@description('No inventory client secret: the inventory app trusts the managed identity of this Container App through workload identity federation. Off keeps the client secret.')
param useFederation bool = false

@description('Keep AIO\'s own data (templates, documentation notes, audit records) on an Azure Files share mounted at /app/.cloudshift, so it survives restarts and updates. Without it that data lives only in the running container.')
param persistentStorage bool = true

var suffix = uniqueString(resourceGroup().id)
var roles = {
  acrPull: '7f951dda-4ed3-4680-a7ca-43fe172d538d'
  keyVaultSecretsUser: '4633458b-17de-408a-b874-0445c86b69e6'
  keyVaultSecretsOfficer: 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
}
// With federation the inventory app has no secret, so graph-client-secret is not referenced at all.
var secretNames = useFederation
  ? ['nextauth-secret', 'entra-client-secret']
  : ['nextauth-secret', 'entra-client-secret', 'graph-client-secret']
// Add user needs only its flag: there is no separate write app, client ID or secret.
var userAdminEnv = enableUserAdmin ? [{ name: 'CLOUDSHIFT_ENABLE_USER_ADMIN', value: 'true' }] : []
// Azure Virtual Desktop needs only its flag: no role assignment, identity or secret is added for it.
var avdEnv = enableAvd ? [{ name: 'CLOUDSHIFT_ENABLE_AVD', value: 'true' }] : []
// Inventory credential: the identity's client ID for federation, otherwise the Key Vault secret.
var graphCredentialEnv = useFederation
  ? [{ name: 'CLOUDSHIFT_FEDERATED_IDENTITY_CLIENT_ID', value: identity.properties.clientId }]
  : [{ name: 'GRAPH_CLIENT_SECRET', secretRef: 'graph-client-secret' }]
// Container user (Dockerfile: uid/gid 10001) owns the share; only that user can read or write it.
var dataMountOptions = 'uid=10001,gid=10001,dir_mode=0700,file_mode=0600,nobrl'
var dataVolumes = persistentStorage
  ? [{ name: 'data', storageType: 'AzureFile', storageName: 'cloudshift-data', mountOptions: dataMountOptions }]
  : []
var dataMounts = persistentStorage ? [{ volumeName: 'data', mountPath: '/app/.cloudshift' }] : []
// Set only when a group is configured.
var operatorGroupEnv = empty(operatorGroupId) ? [] : [{ name: 'CLOUDSHIFT_OPERATOR_GROUP_ID', value: operatorGroupId }]

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${name}-logs-${suffix}'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${name}-identity'
  location: location
}

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: take('${replace(name, '-', '')}${suffix}', 50)
  location: location
  sku: { name: 'Basic' }
  properties: {
    adminUserEnabled: false
  }
}

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-${suffix}'
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 30
  }
}

resource identityPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, identity.id, roles.acrPull)
  scope: registry
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.acrPull)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource identitySecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, identity.id, roles.keyVaultSecretsUser)
  scope: vault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.keyVaultSecretsUser)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource deployerSecrets 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, deployerObjectId, roles.keyVaultSecretsOfficer)
  scope: vault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.keyVaultSecretsOfficer)
    principalId: deployerObjectId
    principalType: deployerPrincipalType
  }
}

resource appEnvironment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${name}-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
  }
}

// AIO's private data share. Container Apps without a virtual network mounts Azure Files over SMB with the
// account key, so shared-key access and the public endpoint stay on; HTTPS/SMB 3 encryption and TLS 1.2 are
// required, blob public access is off, and the key is held only by the Container Apps environment.
resource dataAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = if (persistentStorage) {
  name: take('st${suffix}', 24)
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: true
    publicNetworkAccess: 'Enabled'
  }
}

resource dataFiles 'Microsoft.Storage/storageAccounts/fileServices@2023-05-01' = if (persistentStorage) {
  parent: dataAccount
  name: 'default'
  properties: {
    shareDeleteRetentionPolicy: { enabled: true, days: 14 }
  }
}

resource dataShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-05-01' = if (persistentStorage) {
  parent: dataFiles
  name: 'cloudshift-data'
  properties: { shareQuota: 5, enabledProtocols: 'SMB' }
}

// Anyone who can list the account key (Contributor on the group) can mount the share, so record every
// file read, write and delete in the existing Log Analytics workspace.
resource dataFilesDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (persistentStorage) {
  name: 'cloudshift-data-access'
  scope: dataFiles
  properties: {
    workspaceId: logs.id
    logs: [
      { category: 'StorageRead', enabled: true }
      { category: 'StorageWrite', enabled: true }
      { category: 'StorageDelete', enabled: true }
    ]
  }
}

resource dataStorage 'Microsoft.App/managedEnvironments/storages@2024-03-01' = if (persistentStorage) {
  parent: appEnvironment
  name: 'cloudshift-data'
  properties: {
    azureFile: {
      accountName: dataAccount.name
      accountKey: dataAccount.listKeys().keys[0].value
      shareName: dataShare.name
      accessMode: 'ReadWrite'
    }
  }
}

var appUrl = 'https://${name}.${appEnvironment.properties.defaultDomain}'
var useCustomDomain = !empty(customDomain) && !empty(customDomainCertificateId)
// Sign-in must use the address people browse to; switch only once the certificate is bound.
var publicUrl = useCustomDomain ? 'https://${customDomain}' : appUrl

resource app 'Microsoft.App/containerApps@2024-03-01' = if (deployApp) {
  name: name
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identity.id}': {} }
  }
  dependsOn: [identityPull, identitySecrets, dataStorage]
  properties: {
    managedEnvironmentId: appEnvironment.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 3000
        transport: 'auto'
        allowInsecure: false
        // Redeploys keep a bound domain; leaving it out would remove the binding.
        customDomains: useCustomDomain
          ? [{ name: customDomain, certificateId: customDomainCertificateId, bindingType: 'SniEnabled' }]
          : []
      }
      registries: [{ server: registry.properties.loginServer, identity: identity.id }]
      secrets: [
        for secret in secretNames: {
          name: secret
          keyVaultUrl: '${vault.properties.vaultUri}secrets/${secret}'
          identity: identity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'cloudshift'
          image: image
          resources: { cpu: json('0.5'), memory: '1Gi' }
          volumeMounts: dataMounts
          env: concat([
            { name: 'NODE_ENV', value: 'production' }
            // Container Apps sets HOSTNAME to the replica name; the server must bind all interfaces.
            { name: 'HOSTNAME', value: '0.0.0.0' }
            { name: 'CLOUDSHIFT_DEMO_MODE', value: 'false' }
            { name: 'NEXTAUTH_URL', value: publicUrl }
            { name: 'NEXTAUTH_SECRET', secretRef: 'nextauth-secret' }
            { name: 'ENTRA_TENANT_ID', value: entraTenantId }
            { name: 'ENTRA_CLIENT_ID', value: entraClientId }
            { name: 'ENTRA_CLIENT_SECRET', secretRef: 'entra-client-secret' }
            { name: 'GRAPH_CLIENT_ID', value: graphClientId }
          ], graphCredentialEnv, [
            { name: 'CLOUDSHIFT_OPERATOR_IDS', value: operatorIds }
            { name: 'CLOUDSHIFT_TENANTS_JSON', value: tenantsJson }
          ], operatorGroupEnv, userAdminEnv, avdEnv)
          probes: [
            {
              type: 'Startup'
              httpGet: { path: '/login', port: 3000 }
              initialDelaySeconds: 3
              periodSeconds: 5
              failureThreshold: 24
            }
            {
              type: 'Readiness'
              httpGet: { path: '/login', port: 3000 }
              periodSeconds: 15
            }
            {
              type: 'Liveness'
              tcpSocket: { port: 3000 }
              periodSeconds: 30
            }
          ]
        }
      ]
      volumes: dataVolumes
      // In-memory token caches and local file locks assume one replica.
      scale: { minReplicas: 1, maxReplicas: 1 }
    }
  }
}

output appUrl string = appUrl
output publicUrl string = publicUrl
output environmentName string = appEnvironment.name
output registryName string = registry.name
output registryServer string = registry.properties.loginServer
output vaultName string = vault.name
// Federated identity credentials use the principal (object) ID as subject; the app selects the
// identity by its client ID.
output identityClientId string = identity.properties.clientId
output identityPrincipalId string = identity.properties.principalId
output dataShareName string = persistentStorage ? 'cloudshift-data' : ''
