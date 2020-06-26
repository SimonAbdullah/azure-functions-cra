using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using DnsClient;

namespace CertificateRenewal.ACME
{
    public static class DNSUtils
    {
        private static LookupClient _client;

        public static void InitClient(List<string> dnsServers)
        {
            if (_client == null)
            {
                lock (typeof(DNSUtils))
                {
                    if (_client == null)
                    {
                        IPAddress[] nameServers = { };
                        if (dnsServers?.Count > 0)
                        {
                            nameServers = dnsServers.SelectMany(x => Dns.GetHostAddresses(x)).ToArray();
                        }


                        var clientOptions = new LookupClientOptions(nameServers)
                        {
                            UseCache= false
                        };

                        _client = new LookupClient(clientOptions);
                    }
                }
            }
        }

        public static async Task<IEnumerable<string>> LookupRecordAsync(string type, string name)
        {
            var dnsType = (QueryType)Enum.Parse(typeof(QueryType), type);
            var dnsResp = await _client.QueryAsync(name, dnsType);

            if (dnsResp.HasError)
            {
                if ("Non-Existent Domain".Equals(dnsResp.ErrorMessage,
                        StringComparison.OrdinalIgnoreCase))
                    return null;
                throw new Exception("DNS lookup error:  " + dnsResp.ErrorMessage);
            }

            return dnsResp.AllRecords.Select(x => x.ToString());
        }

        public static async Task AddGoDaddyDNSTXTRecordAsync(string domain, string key, string secret, string txtValue)
        {
            var maxRetries = 10;

            var type = "TXT";
            var name = "_acme-challenge";

            var url = string.Format("https://api.godaddy.com/v1/domains/{0}/records/{1}/{2}", domain, type, name);

            using (var httpClient = new HttpClient())
            {
                httpClient.DefaultRequestHeaders.Add("Authorization", $"sso-key {key}:{secret}");
                httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                httpClient.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/json; charset=utf-8");

                var requestPayload = new List<object>() {
                    new {
                        data = txtValue,
                        name,
                        type
                    }
                };

                while (maxRetries-- > 0)
                {
                    var result = await httpClient.PutAsJsonAsync(url, requestPayload);
                    if (result.StatusCode == HttpStatusCode.OK) break;
                }
            }
        }
    }
}
