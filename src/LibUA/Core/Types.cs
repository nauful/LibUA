using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LibUA
{
    namespace Core
    {
        public static class Types
        {
            public static bool StatusCodeIsGood(uint code) { return (code & 0xC0000000) == 0; }
            public static bool StatusCodeIsUncertain(uint code) { return (code & 0x40000000) != 0; }
            public static bool StatusCodeIsBad(uint code) { return (code & 0x80000000) != 0; }

            public static string[] SLSecurityPolicyUris =
            {
                "invalid",
                "http://opcfoundation.org/UA/SecurityPolicy#None",
                "http://opcfoundation.org/UA/SecurityPolicy#Basic256",
                "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15",
                "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
                "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep",
                "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss",
            };

            public const string TransportProfileBinary = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary";
            public const string SignatureAlgorithmSha1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
            public const string SignatureAlgorithmSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            public const string SignatureAlgorithmRsa15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
            public const string SignatureAlgorithmRsaOaep = "http://www.w3.org/2001/04/xmlenc#rsa-oaep";
            public const string SignatureAlgorithmRsaOaep256 = "http://opcfoundation.org/UA/security/rsa-oaep-sha2-256";
            public const string SignatureAlgorithmRsaPss256 = "http://opcfoundation.org/UA/security/rsa-pss-sha2-256";

            public const string IdentityTokenAnonymous = "anonymous";
        }
    }
}
