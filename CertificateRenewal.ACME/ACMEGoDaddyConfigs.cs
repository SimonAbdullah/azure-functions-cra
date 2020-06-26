using System.Collections.Generic;

namespace CertificateRenewal.ACME
{
    public class ACMEGoDaddyConfigs
    {
        public List<string> Domains { get; set; }
        public List<string> NameServers { get; set; }
        public List<string> Emails { get; set; }
        public string ExportPfxPassword { get; set; }
        public string BaseDomain { get; set; }
        public string GoDaddyApiKey { get; set; }
        public string GoDaddyApiSecret { get; set; }
        public string WorkingDirectory { get; set; }


        public ACMEGoDaddyConfigs(
            List<string> domains,
            List<string> nameServers, 
            List<string> emails,
            string baseDomain, 
            string exportPfxPassword, 
            string goDaddyApiKey, 
            string goDaddyApiSecret,
            string workingDirectory = "./")
        {
            Domains = domains;
            NameServers = nameServers;
            Emails = emails;
            ExportPfxPassword = exportPfxPassword;
            BaseDomain = baseDomain;
            GoDaddyApiKey = goDaddyApiKey;
            GoDaddyApiSecret = goDaddyApiSecret;
            WorkingDirectory = workingDirectory;
        }
    }
}