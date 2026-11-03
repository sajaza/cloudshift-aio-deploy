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

@description('JSON allowlist of approved customer tenants.')
param tenantsJson string = '[]'

@description('Optional custom hostname such as aio.contoso.com, already bound with a managed certificate.')
param customDomain string = ''

@description('Resource ID of the managed certificate for customDomain. Both must be set to use the domain.')
param customDomainCertificateId string = ''

@description('Optional user creation through the separate cloudshift user admin app (User.ReadWrite.All only). Its secret must already be in Key Vault as useradmin-client-secret.')
param enableUserAdmin bool = false

@description('Client ID of the cloudshift user admin app registration. Used only when enableUserAdmin is true.')
param userAdminClientId string = ''

var suffix = uniqueString(resourceGroup().id)
var roles = {
  acrPull: '7f951dda-4ed3-4680-a7ca-43fe172d538d'
  keyVaultSecretsUser: '4633458b-17de-408a-b874-0445c86b69e6'
  keyVaultSecretsOfficer: 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7'
}
var baseSecretNames = ['nextauth-secret', 'entra-client-secret', 'graph-client-secret']
// Referenced only when user creation is on, so a disabled deploy never points at a missing secret.
var secretNames = enableUserAdmin ? concat(baseSecretNames, ['useradmin-client-secret']) : baseSecretNames
var userAdminEnv = enableUserAdmin
  ? [
      { name: 'CLOUDSHIFT_ENABLE_USER_ADMIN', value: 'true' }
      { name: 'USERADMIN_CLIENT_ID', value: userAdminClientId }
      { name: 'USERADMIN_CLIENT_SECRET', secretRef: 'useradmin-client-secret' }
    ]
  : []

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
  dependsOn: [identityPull, identitySecrets]
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
            { name: 'GRAPH_CLIENT_SECRET', secretRef: 'graph-client-secret' }
            { name: 'CLOUDSHIFT_OPERATOR_IDS', value: operatorIds }
            { name: 'CLOUDSHIFT_TENANTS_JSON', value: tenantsJson }
          ], userAdminEnv)
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
