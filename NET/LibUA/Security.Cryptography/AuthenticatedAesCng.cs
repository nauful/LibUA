// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     <para>
    ///         The AuthenticatedAesCng class provides a wrapper for the CNG implementation of the
    ///         authenticated AES algorithm. AesCng uses the BCrypt layer of CNG to do its work, and requires
    ///         Windows Vista SP1 and the .NET Framework 3.5.
    ///     </para>
    ///     <para>
    ///         More information on using AuthenticatedAesCng can be found here:
    ///         http://blogs.msdn.com/shawnfa/archive/2009/03/17/authenticated-symmetric-encryption-in-net.aspx
    ///     </para>
    ///     <para>
    ///         Since most of the AuthenticatedAesCng APIs are inherited from the
    ///         <see cref="AuthenticatedSymmetricAlgorithm" /> base class, see the documentation for
    ///         AuthenticatedSymmetricAlgorithm for a complete API description.
    ///     </para>
    ///     <para>
    ///         Example usage - encrypting and authenticating data using GCM
    ///         <example>
    ///             // Encrypt and authenticate data stored in byte array plaintext, using a key and IV.
    ///             // Additionally, provide data that is required to validate the authentication tag, but
    ///             // which does not get added into the ciphertext.
    ///             using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
    ///             {
    ///                 aes.Key = GetEncryptionKey();
    ///                 aes.IV = GetNonce();
    ///                 aes.CngMode = CngChainingMode.Gcm;
    ///
    ///                 // This data is required to verify the authentication tag, but will not go into the
    ///                 // ciphertext
    ///                 aes.AuthenticatedData = GetAdditionalAuthenticationData();
    ///
    ///                 // Do the encryption
    ///                 using (MemoryStream ms = new MemoryStream())
    ///                 using (IAuthenticatedCryptoTransform encryptor = aes.CreateAuthenticatedEncryptor())
    ///                 using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
    ///                 {
    ///                     // Encrypt the plaintext
    ///                     byte[] plaintext = GetPlaintext();
    ///                     cs.Write(paintext, 0, paintext.Length);
    ///
    ///                     // Complete the encryption operation, and generate the authentication tag
    ///                     cs.FlushFinalBlock();
    ///
    ///                     // Get the generated ciphertext and authentication tag
    ///                     byte[] ciphertext = ms.ToArray();
    ///                     byte[] authenticationTag = encryptor.GetTag();
    ///                 }
    ///             }
    ///         </example>
    ///     </para>
    ///     <para>
    ///         Example usage - Decrypting and verifying data using GCM
    ///         <example>
    ///             // Decrypt and authenticate data stored in byte array ciphertext, using a key and IV. 
    ///             // Additionally, provide data that is required to validate the authentication tag, but
    ///             which does not get added into the ciphertext.
    ///             using (AuthenticatedAesCng aes = new AuthenticatedAesCng())
    ///             {
    ///                 aes.Key = GetEncryptionKey();
    ///                 aes.IV = GetNonce();
    ///                 aes.CngMode = CngChainingMode.Gcm;
    ///
    ///                 // This data is required to verify the authentication tag, but will not go into the
    ///                 // ciphertext
    ///                 aes.AuthenticatedData = GetAdditionalAuthenticationData();
    ///
    ///                 // The authentication tag was generated during the encryption operation.
    ///                 aes.Tag = GetAuthenticationTag();
    ///
    ///                 // Do the decryption and authentication
    ///                 using (MemoryStream ms = new MemoryStream())
    ///                 using (ICryptoTransform decryptor = aes.CreateDecryptor())
    ///                 using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
    ///                 {
    ///                     // Decrypt the ciphertext
    ///                     byte[] ciphertext = GetCiphertext();
    ///                     cs.Write(ciphertext, 0, ciphertext.Length);
    ///
    ///                     // If the authentication tag does not validate, this call will throw a
    ///                     // CryptographicException.
    ///                     cs.FlushFinalBlock();
    ///
    ///                     // Get the decrypted and authenticated plaintext
    ///                     byte[] decrypted = ms.ToArray();
    ///                 }
    ///             }
    ///         </example>
    ///     </para>
    /// </summary>
    public sealed class AuthenticatedAesCng : AuthenticatedAes, ICngSymmetricAlgorithm
    {
        private readonly BCryptAuthenticatedSymmetricAlgorithm m_authenticatedSymmetricAlgorithm;

        /// <summary>
        ///     Constructs an AuthenticatedAesCng object. The default settings for this object are:
        ///     <list type="bullet">
        ///         <item>Provider - Microsoft Primitive Algorithm Provider</item>
        ///         <item>CngMode - CngChainingMode.Gcm</item>
        ///     </list>
        /// </summary>
        public AuthenticatedAesCng()
            : this(CngProvider2.MicrosoftPrimitiveAlgorithmProvider)
        {
        }

        /// <summary>
        ///     Construct an AuthenticatedAesCng using a specific algorithm provider.  The default settings
        ///     for this object are:
        ///     <list type="bullet">
        ///         <item>CngMode - CngChainingMode.Gcm</item>
        ///     </list>
        /// </summary>
        /// <param name="provider">algorithm provider to use for AES computation</param>
        /// <exception cref="ArgumentNullException">if <paramref name="provider"/> is null</exception>
        public AuthenticatedAesCng(CngProvider provider)
        {
            if (provider == null)
                throw new ArgumentNullException("provider");

            m_authenticatedSymmetricAlgorithm =
                new BCryptAuthenticatedSymmetricAlgorithm(CngAlgorithm2.Aes,
                                                          provider,
                                                          LegalBlockSizesValue,
                                                          LegalKeySizesValue)
                {
                    // Propigate the default properties from the Aes class to the implementation algorithm.
                    BlockSize = BlockSizeValue,
                    KeySize = KeySizeValue,
                    Padding = PaddingValue
                };
        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing && m_authenticatedSymmetricAlgorithm != null)
                {
                    (m_authenticatedSymmetricAlgorithm as IDisposable).Dispose();
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        //
        // Forwarded APIs
        //

        public override byte[] AuthenticatedData
        {
            get { return m_authenticatedSymmetricAlgorithm.AuthenticatedData; }
            set { m_authenticatedSymmetricAlgorithm.AuthenticatedData = value; }
        }

        public override int BlockSize
        {
            get { return m_authenticatedSymmetricAlgorithm.BlockSize; }
            set { m_authenticatedSymmetricAlgorithm.BlockSize = value; }
        }

        /// <summary>
        ///     Gets a value determining if the AES object supports chaining multiple encryption calls, or if
        ///     all encryption or decryption must be done at once. Generally, this value won't matter to code
        ///     running against the AuthenticatedAesCng object, since the transforms produced by
        ///     AuthenticatedAesCng will take chaining support into account to ensure that only one call to
        ///     CNG is made if that is required.
        /// </summary>
        public bool ChainingSupported
        {
            get { return m_authenticatedSymmetricAlgorithm.ChainingSupported; }
        }

        /// <summary>
        ///     Gets or sets the CNG cipher mode to use during encryption or decryption. This mode must be an
        ///     authenticating chaining mode, currently:
        ///     <list type="bullet">
        ///         <item>CngChainingMode.Ccm</item>
        ///         <item>CngChainingMode.Gcm</item>
        ///     </list>
        /// </summary>
        public CngChainingMode CngMode
        {
            get { return m_authenticatedSymmetricAlgorithm.CngMode; }
            set { m_authenticatedSymmetricAlgorithm.CngMode = value; }
        }

        public override int FeedbackSize
        {
            get { return m_authenticatedSymmetricAlgorithm.FeedbackSize; }
            set { m_authenticatedSymmetricAlgorithm.FeedbackSize = value; }
        }

        public override byte[] IV
        {
            get { return m_authenticatedSymmetricAlgorithm.IV; }
            set { m_authenticatedSymmetricAlgorithm.IV = value; }
        }

        public override byte[] Key
        {
            get { return m_authenticatedSymmetricAlgorithm.Key; }
            set { m_authenticatedSymmetricAlgorithm.Key = value; }
        }

        public override int KeySize
        {
            get { return m_authenticatedSymmetricAlgorithm.KeySize; }
            set { m_authenticatedSymmetricAlgorithm.KeySize = value; }
        }

        public override KeySizes[] LegalBlockSizes
        {
            get { return m_authenticatedSymmetricAlgorithm.LegalBlockSizes; }
        }

        public override KeySizes[] LegalKeySizes
        {
            get { return m_authenticatedSymmetricAlgorithm.LegalBlockSizes; }
        }

        public override KeySizes[] LegalTagSizes
        {
            get { return m_authenticatedSymmetricAlgorithm.LegalTagSizes; }
        }

        public override CipherMode Mode
        {
            get { return m_authenticatedSymmetricAlgorithm.Mode; }
            set { m_authenticatedSymmetricAlgorithm.Mode = value; }
        }

        public override PaddingMode Padding
        {
            get { return m_authenticatedSymmetricAlgorithm.Padding; }
            set { m_authenticatedSymmetricAlgorithm.Padding = value; }
        }

        public CngProvider Provider
        {
            get { return m_authenticatedSymmetricAlgorithm.Provider; }
        }

        public override byte[] Tag
        {
            get { return m_authenticatedSymmetricAlgorithm.Tag; }
            set { m_authenticatedSymmetricAlgorithm.Tag = value; }
        }

        public override int TagSize
        {
            get { return m_authenticatedSymmetricAlgorithm.TagSize; }
            set { m_authenticatedSymmetricAlgorithm.TagSize = value; }
        }

        public override IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor()
        {
            return m_authenticatedSymmetricAlgorithm.CreateAuthenticatedEncryptor();
        }

        public override IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return m_authenticatedSymmetricAlgorithm.CreateAuthenticatedEncryptor(rgbKey, rgbIV);
        }

        public override IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor(byte[] rgbKey,
                                                                                   byte[] rgbIV,
                                                                                   byte[] rgbAuthenticatedData)
        {
            return m_authenticatedSymmetricAlgorithm.CreateAuthenticatedEncryptor(rgbKey, rgbIV, rgbAuthenticatedData);
        }

        public override ICryptoTransform CreateDecryptor()
        {
            return m_authenticatedSymmetricAlgorithm.CreateDecryptor();
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return m_authenticatedSymmetricAlgorithm.CreateDecryptor(rgbKey, rgbIV);
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey,
                                                         byte[] rgbIV,
                                                         byte[] rgbAuthenticatedData,
                                                         byte[] rgbTag)
        {
            return m_authenticatedSymmetricAlgorithm.CreateDecryptor(rgbKey, rgbIV, rgbAuthenticatedData, rgbTag);
        }

        public override ICryptoTransform CreateEncryptor()
        {
            return m_authenticatedSymmetricAlgorithm.CreateEncryptor();
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return m_authenticatedSymmetricAlgorithm.CreateEncryptor(rgbKey, rgbIV);
        }

        public override void GenerateIV()
        {
            m_authenticatedSymmetricAlgorithm.GenerateIV();
        }

        public override void GenerateKey()
        {
            KeyValue = RNGCng.GenerateKey(KeySizeValue / 8);
        }
    }
}
