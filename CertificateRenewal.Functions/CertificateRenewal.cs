using System;
using System.IO;
using System.Linq;
using Microsoft.Rest;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using CertificateRenewal.ACME;
using Microsoft.Azure.KeyVault;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Microsoft.Azure.Management.Fluent;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.Management.AppService.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.AppService.Fluent.Models;
using FluentAzure = Microsoft.Azure.Management.Fluent.Azure;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;

namespace CertificateRenewal.Functions
{
    public static class HTTPEndpoint
    {
        private static readonly string _baseDomain = " BASE DOMAIN";
        private static readonly List<string> _emails = new List<string>() { "EMAIL" };
        private static readonly List<string> _nameServers = new List<string>() { "NAME SERVER" };
        private static readonly List<string> _domains = new List<string>() { "DOMAIN or SUBDOMAINs" };

        private static readonly string _tenantId = "TENANT ID";
        private static readonly string _subscriptionId = "TENANT ID";
        private static readonly string _keyVaultStore = "KEY VAULT URL";
        private static readonly string _resourceGroupName = "AZURE RESOURCE GROUP";
        private static readonly string _appServiceRegion = "AZURE APP SERVICE REGION";

        private static readonly List<(string Domain, string AppName)> _domainsAndAppsInScope =
            new List<(string Domain, string AppName)>() { ("AZURE WEB APP CUSTOM DOMAIN", "AZURE WEB APP NAME") };

        private const string _pfxPasswordAKVSecretName = "PFX PASSWORD AKV SECRET NAME";
        private const string _goDaddyAPIKeyAKVSecretName = "GoDaddy API KEY AKV SECRET NAME";
        private const string _goDaddyAPISecretAKVSecretName = "GoDaddy API SECRET AKV SECRET NAME";



        private static KeyVaultClient _keyVaultClient = null;

        [FunctionName("CertificateRenewal")]
        public static async Task Run([TimerTrigger("0 0 0 */2 * *")] TimerInfo myTimer, ILogger log)
        {
            var configs = GetSecretsForCertificateRenewalAsync().Result;

            var acmeClient = new ACMEClient();
            var godaddyConfigs = new ACMEGoDaddyConfigs(
                _domains,
                _nameServers,
                _emails,
                _baseDomain,
                configs.ExportPfxPassword,
                configs.GoDaddyApiKey,
                configs.GoDaddyApiSecret,
                Path.GetTempPath());
            var generatedCert = acmeClient.GetNewCertificatePfxFileAsync(godaddyConfigs).Result;

            await DeleteOldCertificatesAsync();
            await UploadAndBindNewCertificateAsync(generatedCert, configs.ExportPfxPassword);
        }

        private static async Task UploadAndBindNewCertificateAsync((System.Security.Cryptography.X509Certificates.X509Certificate2 Certificate, byte[] PFXBytes) generatedCert, string pfxPassword)
        {
            var azure = await GetAzureAsync();
            var certificate = await azure.AppServices.AppServiceCertificates
                .Define(Guid.NewGuid().ToString())
                .WithRegion(_appServiceRegion)
                .WithExistingResourceGroup(_resourceGroupName)
                .WithPfxByteArray(generatedCert.PFXBytes)
                .WithPfxPassword(pfxPassword)
                .CreateAsync();

            _domainsAndAppsInScope.ForEach(domainApp =>
            {
                azure.WebApps.Inner
                .CreateOrUpdateHostNameBindingAsync(
                _resourceGroupName,
                domainApp.AppName,
                domainApp.Domain,
                new HostNameBindingInner(
                        azureResourceType: AzureResourceType.Website,
                        hostNameType: HostNameType.Verified,
                        customHostNameDnsRecordType: CustomHostNameDnsRecordType.CName,
                        sslState: SslState.SniEnabled,
                        thumbprint: generatedCert.Certificate.Thumbprint)
                ).GetAwaiter().GetResult();
            });
        }

        private static async Task DeleteOldCertificatesAsync(List<string> logs = null)
        {
            if (logs == null) logs = new List<string>();

            var azure = await GetAzureAsync();

            // Delete bindings
            var webApps = await azure.WebApps.ListByResourceGroupAsync(_resourceGroupName);
            webApps.ToList().ForEach(async app =>
            {
                var domainName = _domainsAndAppsInScope.FirstOrDefault(d => app.HostNames.Any(hn => hn.Equals(d.Domain, StringComparison.OrdinalIgnoreCase)));
                logs.Add("Deleting bindings: " + domainName);
                await azure.WebApps.Inner
                .CreateOrUpdateHostNameBindingAsync(
                _resourceGroupName,
                app.Name,
                domainName.Domain,
                new HostNameBindingInner(
                        azureResourceType: AzureResourceType.Website,
                        hostNameType: HostNameType.Verified,
                        customHostNameDnsRecordType: CustomHostNameDnsRecordType.CName,
                        sslState: SslState.Disabled)
                );
            });

            // Delete imported certificates
            var certificates = await azure.WebApps.Manager.AppServiceCertificates.ListByResourceGroupAsync(_resourceGroupName);
            var certificateIdsToDelete = certificates
                .Where(cert => cert.HostNames.Any(hn => _domainsAndAppsInScope.Any(d => d.Domain.Equals(hn, StringComparison.OrdinalIgnoreCase))))
                .Distinct()
                .Select(cert => cert.Id)
                .ToList();
            certificateIdsToDelete.ForEach(async certificateId => await azure.WebApps.Manager.AppServiceCertificates.DeleteByIdAsync(certificateId));
        }

        private static async Task<(string GoDaddyApiKey, string GoDaddyApiSecret, string ExportPfxPassword)> GetSecretsForCertificateRenewalAsync()
        {
            var client = GetKeyVaultClient();

            var godaddyApiKey = (await client.GetSecretAsync(_keyVaultStore, _goDaddyAPIKeyAKVSecretName)).Value;
            var godaddyApiSecret = (await client.GetSecretAsync(_keyVaultStore, _goDaddyAPISecretAKVSecretName)).Value;
            var exprotPfxPassword = (await client.GetSecretAsync(_keyVaultStore, _pfxPasswordAKVSecretName)).Value;

            return (godaddyApiKey, godaddyApiSecret, exprotPfxPassword);
        }

        private static KeyVaultClient GetKeyVaultClient()
        {
            if (_keyVaultClient == null)
            {
                AzureServiceTokenProvider azureServiceTokenProvider =
                    new AzureServiceTokenProvider();
                _keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));

            }
            return _keyVaultClient;
        }

        private static async Task<IAzure> GetAzureAsync()
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var token = await azureServiceTokenProvider.GetAccessTokenAsync("https://management.azure.com", _tenantId);
            var tokenCredentials = new TokenCredentials(token);
            var azure = FluentAzure
                .Configure()
                .WithLogLevel(HttpLoggingDelegatingHandler.Level.Basic)
                .Authenticate(new AzureCredentials(
                    tokenCredentials,
                    tokenCredentials,
                    _tenantId,
                    AzureEnvironment.AzureGlobalCloud))
                .WithSubscription(_subscriptionId);

            return azure;
        }
    }
}