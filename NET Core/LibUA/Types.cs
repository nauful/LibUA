
// Type: LibUA.Core.Types

namespace LibUA.Core
{
    public static class Types
    {
        public static string[] SLSecurityPolicyUris = new string[5]
        {
      "invalid",
      "http://opcfoundation.org/UA/SecurityPolicy#None",
      "http://opcfoundation.org/UA/SecurityPolicy#Basic256",
      "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15",
      "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
        };
        public const string TransportProfileBinary = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary";
        public const string SignatureAlgorithmSha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
        public const string SignatureAlgorithmSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        public const string SignatureAlgorithmRsa15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
        public const string IdentityTokenAnonymous = "anonymous";

        public static bool StatusCodeIsGood(uint code)
        {
            return ((int)code & -1073741824) == 0;
        }

        public static bool StatusCodeIsUncertain(uint code)
        {
            return (code & 1073741824U) > 0U;
        }

        public static bool StatusCodeIsBad(uint code)
        {
            return (code & 2147483648U) > 0U;
        }
    }
}
