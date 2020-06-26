using System;
using System.Collections.Generic;

namespace CertificateRenewal.ACME
{
    public static class Constants
    {
        public const string LetsEncryptName = "LetsEncrypt";
        public const string LetsEncryptStagingName = "LetsEncryptStaging";

        public const string LetsEncryptV2StagingEndpoint = "https://acme-staging-v02.api.letsencrypt.org/";
        public const string LetsEncryptV2Endpoint = "https://acme-v02.api.letsencrypt.org/";

        public static readonly IReadOnlyDictionary<string, string> NameUrlMap =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [LetsEncryptName] = LetsEncryptV2Endpoint,
                [LetsEncryptStagingName] = LetsEncryptV2StagingEndpoint,
            };

        public const string Dns01ChallengeType = "dns-01";
        public const string Http01ChallengeType = "http-01";

        public const string RsaKeyType = "rsa";
        public const string EcKeyType = "ec";

        public static readonly IReadOnlyDictionary<string, int> DefaultAlgorKeySizeMap =
            new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
            {
                [RsaKeyType] = 2048,
                [EcKeyType] = 256,
            };

        public const string AcmeDirectoryFile = "00-ServiceDirectory";
        public const string AcmeAccountDetailsFile = "10-AccountDetails";
        public const string AcmeAccountKeyFile = "15-AccountKey";
        /// Name format for orders directory.
        public const string AcmeOrdersDir = "50-Orders";
        /// Name format with an argument of Order ID.
        public const string AcmeOrdersDirFmt = AcmeOrdersDir + "/{0}";
        /// Name format with an argument of Order ID.
        public const string AcmeOrderDetailsFileFmt = AcmeOrdersDir + "/{0}/0-Order";
        /// Name format with arguments of Order ID and Authorization ID.
        public const string AcmeOrderAuthzDetailsFileFmt = AcmeOrdersDir + "/{0}/2-Authz_{1}";
        /// Name format with arguments of Order ID, Authorization ID and Challenge Type.
        public const string AcmeOrderAuthzChlngDetailsFileFmt = AcmeOrdersDir + "/{0}/4-AuthzChlng_{1}_{2}";
        /// Name format with an argument of Order ID.
        public const string AcmeOrderCertKeyFmt = AcmeOrdersDir + "/{0}/6-CertKey";
        /// Name format with an argument of Order ID.
        public const string AcmeOrderCertCsrFmt = AcmeOrdersDir + "/{0}/7-CsrDer";
        /// Name format with an argument of Order ID.
        public const string AcmeOrderCertFmt = AcmeOrdersDir + "/{0}/8-CertChainPem";

        public const string ValidStatus = "valid";
        public const string InvalidStatus = "invalid";
        public const string PendingStatus = "pending";
        public const string ReadyState = "ready";
    }
}
