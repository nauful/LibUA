using System;
using System.Diagnostics;
using System.Globalization;
using System.Security;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{

    /// <summary>
    /// Set of hash algorithms that can be used with PBKDF2. 
    /// Choosing, e.g., SHA-256, with compute PBKDF2 with HMAC-SHA256 as
    /// a PRF. 
    /// </summary>
    public static class PBKDF2HashAlgorithm
    {
        public const string SHA1 = BCryptNative.AlgorithmName.Sha1;
        public const string SHA256 = BCryptNative.AlgorithmName.Sha256;
        public const string SHA384 = BCryptNative.AlgorithmName.Sha384;
        public const string SHA512 = BCryptNative.AlgorithmName.Sha512;

        public static bool ValidateHashName(string name)
        {
            if(name != SHA1 && 
               name != SHA256 &&
               name != SHA384 &&
               name != SHA512)
            {
                return false;
            }
            return true;
        }
    }

    /// <summary>
    /// Class containing the API for PBKDF2, a wrapper of the CNG/bcrypt.dll implementation.
    /// </summary>
    public static class BCryptPBKDF2
    {
        /// <summary>
        /// Compute the PBKDF2 function on the given inputs using the CNG implementation in the <c>BCryptKeyDerivation</c> API.
        /// </summary>
        /// <param name="hashName">The hash function to use, must be one of the strings in <seealso cref="PBKDF2HashAlgorithm"/>.</param>
        /// <param name="password">The password, as a byte array (i.e., without a string termination character).</param>
        /// <param name="salt">The salt, a cryptographically random value. Should be 16-bytes or longer.</param>
        /// <param name="cIterations">The number of iterations of PBKDF2 to apply.</param>
        /// <returns>The digest of the password (also sometimes called derived key).  The length of the digest
        /// will be equal to the length of the chosen hash function output.</returns>
        /// <remarks>
        /// See http://msdn.microsoft.com/en-us/library/windows/desktop/hh448506 for a description
        /// of the wrapped function.  Larger values of cIterations will cause the function to use more
        /// CPU time, and will also increase the workfactor for an attacker in a brute-force attack. 
        /// </remarks>
        public static byte[] ComputeHash(string hashName, byte[] password, byte[] salt, Int64 cIterations)
        {
            if (cIterations < 1)
                throw new ArgumentException("Iteration count must be greater than zero.", "cIterations");
            if (salt == null)
                throw new ArgumentException("Salt must be non-null", "salt");
            if (password == null)
                throw new ArgumentException("Password must be non-null", "password");

            if(!PBKDF2HashAlgorithm.ValidateHashName(hashName))
                throw new ArgumentException("Invalid hash name for PBKDF2");

            byte[] digest = null;

            double vers = Environment.OSVersion.Version.Major + Environment.OSVersion.Version.Minor * 0.1;

            if(vers > 6.1)
            { 
                // The BCryptKeyDerivation API is only supported on Win8/Server 2012 and above
                digest = BCryptNative.PBKDF2BCryptKeyDerivation(hashName, password, salt, (UInt64) cIterations);
            }
            else
            {
                // Fall back to BCryptDeriveKeyPBKDF2, which is roughly 2x slower on systems without the KeyDerivation API
                digest = BCryptNative.PBKDF2BCryptDeriveKeyPBKDF2(hashName, password, salt, (UInt64)cIterations);
            }

            return digest;
        }
        
    }
}
