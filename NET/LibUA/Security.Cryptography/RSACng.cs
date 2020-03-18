// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     <para>
    ///         The RSACng class provides a wrapper for the CNG implementation of the RSA algorithm. The
    ///         interface provided by RSACng is derived from the <see cref="RSA" /> base type, and not from
    ///         the <see cref="RSACryptoServiceProvider" /> class. Consequently, it is not a drop in
    ///         replacement for existing uses of RSACryptoServiceProvider.
    ///     </para>
    ///     <para>
    ///         RSACng uses a programming model more similar to the <see cref="ECDsaCng" /> class than
    ///         RSACryptoServiceProvider. For instance, unlike RSACryptoServiceProvider which has a key
    ///         directly tied into the operations of the type itself, the key used by RsaCng is managed by a
    ///         separate <see cref="CngKey" /> object. Additionally, operations such as signing and verifying
    ///         signatures take their parameters from a set of properties set on the RSACng object, similar to
    ///         how ECDsaCng uses properties of its object to control the signing and verification operations.
    ///     </para>
    ///     <para>    
    ///         RSACng uses the NCrypt layer of CNG to do its work, and requires Windows Vista and the .NET
    ///         Framework 3.5.
    ///     </para>
    ///     <para>
    ///         Example usage:
    ///         <example>
    ///             // Create an RSA-SHA256 signature using the key stored in "MyKey"
    ///             byte[] dataToSign = Encoding.UTF8.GetBytes("Data to sign");
    ///             using (CngKey signingKey = CngKey.Open("MyKey");
    ///             using (RSACng rsa = new RSACng(signingKey))
    ///             {
    ///                 rsa.SignatureHashAlgorithm = CngAlgorithm.Sha256;
    ///                 return rsa.SignData(dataToSign);
    ///             }
    ///         </example>
    ///     </para>
    /// </summary>
    [SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "RSA", Justification = "This is for consistency with the existing RSACryptoServiceProvider type")]
    public sealed class RSACng : RSA, ICngAsymmetricAlgorithm
    {
        private static KeySizes[] s_legalKeySizes = new KeySizes[] { new KeySizes(384, 16384, 8) };
        
        // CngKeyBlob formats for RSA key blobs
        private static CngKeyBlobFormat s_rsaFullPrivateBlob = new CngKeyBlobFormat(BCryptNative.KeyBlobType.RsaFullPrivateBlob);
        private static CngKeyBlobFormat s_rsaPrivateBlob = new CngKeyBlobFormat(BCryptNative.KeyBlobType.RsaPrivateBlob);
        private static CngKeyBlobFormat s_rsaPublicBlob = new CngKeyBlobFormat(BCryptNative.KeyBlobType.RsaPublicBlob);

        // Key handle
        private CngKey m_key;

        // Properties used when encrypting or decrypting
        private AsymmetricPaddingMode m_encryptionPaddingMode = AsymmetricPaddingMode.Oaep;
        private CngAlgorithm m_encryptionHashAlgorithm = CngAlgorithm.Sha256;

        // Properties used when signing or verifying data
        private AsymmetricPaddingMode m_signaturePaddingMode = AsymmetricPaddingMode.Pkcs1;
        private CngAlgorithm m_signatureHashAlgorithm = CngAlgorithm.Sha256;
        private int m_signatureSaltBytes = 20;

        /// <summary>
        ///     Create an RSACng algorithm with a random 2048 bit key pair.
        /// </summary>
        public RSACng() : this(2048)
        {
            return;
        }

        /// <summary>
        ///     Creates a new RSACng object that will use a randomly generated key of the specified size.
        ///     Valid key sizes range from 384 to 16384 bits, in increments of 8. It's suggested that a
        ///     minimum size of 2048 bits be used for all keys.
        /// </summary>
        /// <param name="keySize">size of hte key to generate, in bits</param>
        /// <exception cref="CryptographicException">if <paramref name="keySize" /> is not valid</exception>
        public RSACng(int keySize)
        {
            LegalKeySizesValue = s_legalKeySizes;
            KeySize = keySize;
        }

        /// <summary>
        ///     Creates a new RSACng object that will use the specified key. The key's
        ///     <see cref="CngKey.AlgorithmGroup" /> must be Rsa.
        /// </summary>
        /// <param name="key">key to use for RSA operations</param>
        /// <exception cref="ArgumentException">if <paramref name="key" /> is not an RSA key</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="key" /> is null</exception>
        [SecurityCritical]
        [SecuritySafeCritical]
        public RSACng(CngKey key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            LegalKeySizesValue = s_legalKeySizes;

            new SecurityPermission(SecurityPermissionFlag.UnmanagedCode).Assert();
            Key = CngKey.Open(key.Handle, key.IsEphemeral ? CngKeyHandleOpenOptions.EphemeralKey : CngKeyHandleOpenOptions.None);
            CodeAccessPermission.RevertAssert();
        }

        /// <summary>
        ///     Sets the hash algorithm to use when encrypting or decrypting data using the OAEP padding
        ///     method. This property is only used if data is encrypted or decrypted and the
        ///     EncryptionPaddingMode is set to AsymmetricEncryptionPaddingMode.Oaep. The default value is
        ///     Sha256.
        /// </summary>
        /// <exception cref="ArgumentNullException">if EncryptionHashAlgorithm is set to null</exception>
        public CngAlgorithm EncryptionHashAlgorithm
        {
            get { return m_encryptionHashAlgorithm; }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                m_encryptionHashAlgorithm = value;
            }
        }

        /// <summary>
        ///     Sets the padding mode to use when encrypting or decrypting data. The default value is
        ///     AsymmetricPaddingMode.Oaep.
        /// </summary>
        /// <exception cref="ArgumentNullException">if EncryptionPaddingMOde is set to null</exception>
        public AsymmetricPaddingMode EncryptionPaddingMode
        {
            get { return m_encryptionPaddingMode; }

            set
            {
                if (value != AsymmetricPaddingMode.Oaep &&
                    value != AsymmetricPaddingMode.Pkcs1)
                {
                    throw new ArgumentOutOfRangeException("value");
                }

                m_encryptionPaddingMode = value;
            }
        }

        /// <summary>
        ///     Gets the key that will be used by the RSA object for any cryptographic operation that it uses.
        ///     This key object will be disposed if the key is reset, for instance by changing the KeySize
        ///     property, using ImportParamers to create a new key, or by Disposing of the parent RSA object.
        ///     Therefore, you should make sure that the key object is no longer used in these scenarios. This
        ///     object will not be the same object as the CngKey passed to the RSACng constructor if that
        ///     constructor was used, however it will point at the same CNG key.
        /// </summary>
        /// <permission cref="SecurityPermission">
        ///     SecurityPermission/UnmanagedCode is required to read this property.
        /// </permission>
        public CngKey Key
        {
            [SecurityCritical]
            [SecuritySafeCritical]
            [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
            [SecurityPermission(SecurityAction.Assert, UnmanagedCode = true)]
            get
            {
                // If our key size was changed from the key we're using, we need to generate a new key
                if (m_key != null && m_key.KeySize != KeySize)
                {
                    m_key.Dispose();
                    m_key = null;
                }

                // If we don't have a key yet, we need to generate a random one now
                if (m_key == null)
                {
                    CngKeyCreationParameters creationParameters = new CngKeyCreationParameters();
                    CngProperty keySizeProperty = new CngProperty(NCryptNative.KeyPropertyName.Length,
                                                                  BitConverter.GetBytes(KeySize),
                                                                  CngPropertyOptions.None);
                    creationParameters.Parameters.Add(keySizeProperty);
                    m_key = CngKey.Create(CngAlgorithm2.Rsa, null, creationParameters);
                }

                return m_key;
            }

            private set
            {
                Debug.Assert(value != null, "value != null");
                if (value.AlgorithmGroup != CngAlgorithmGroup.Rsa)
                    throw new ArgumentException("KeyMustBeRsa", "value");

                // If we already have a key, clear it out
                if (m_key != null)
                {
                    m_key.Dispose();
                }

                m_key = value;
                KeySize = m_key.KeySize;
            }
        }

        /// <summary>
        ///     Helper property to get the NCrypt key handle
        /// </summary>
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Internal security critical code")]
        private SafeNCryptKeyHandle KeyHandle
        {
            [SecurityCritical]
            [SecurityPermission(SecurityAction.Assert, UnmanagedCode = true)]
            get { return Key.Handle; }
        }

        /// <summary>
        ///     Returns "RSA-PKCS1-KeyEx". This property should not be used.
        /// </summary>
        public override string KeyExchangeAlgorithm
        {
            get { return "RSA-PKCS1-KeyEx";  }
        }

        /// <summary>
        ///     Key storage provider being used for the algorithm
        /// </summary>
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Only exposing provider data.")]
        public CngProvider Provider
        {
            [SecurityCritical]
            [SecuritySafeCritical]
            get { return Key.Provider; }
        }

        /// <summary>
        ///     Returns "http://www.w3.org/2000/09/xmldsig#rsa-sha1". This property should not be used.
        /// </summary>
        public override string SignatureAlgorithm
        {
            get { return "http://www.w3.org/2000/09/xmldsig#rsa-sha1"; }
        }

        /// <summary>
        ///     Gets or sets the hash algorithm to use when signing or verifying data. The default value is
        ///     Sha256.
        /// </summary>
        /// <exception cref="ArgumentNullException">if SignatureHashAlgorithm is set to null</exception>
        public CngAlgorithm SignatureHashAlgorithm
        {
            get { return m_signatureHashAlgorithm; }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                m_signatureHashAlgorithm = value;
            }
        }

        /// <summary>
        ///     Gets or sets the padding mode to use when encrypting or decrypting data. The default value is
        ///     AsymmetricPaddingMode.Pkcs1.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     if SignaturePaddingMode is set to a mode other than Pkcs1 or Pss
        /// </exception>
        public AsymmetricPaddingMode SignaturePaddingMode
        {
            get { return m_signaturePaddingMode; }

            set
            {
                if (value != AsymmetricPaddingMode.Pkcs1 &&
                    value != AsymmetricPaddingMode.Pss)
                {
                    throw new ArgumentOutOfRangeException("value");
                }

                m_signaturePaddingMode = value;
            }
        }

        /// <summary>
        ///     Gets or sets the number of bytes of salt to use when signing data or verifying a signature
        ///     using the PSS padding mode. This property is only used if data is being signed or verified and
        ///     the SignaturePaddingMode is set to AsymmetricEncryptionPaddingMode.Pss. The default value is
        ///     20 bytes.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     if SignatureSaltBytes is set to a negative number
        /// </exception>
        public int SignatureSaltBytes
        {
            get { return m_signatureSaltBytes; }

            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException("value");

                m_signatureSaltBytes = value;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && m_key != null)
            {
                m_key.Dispose();
            }
        }

        /// <summary>
        ///     Build a key container permission that should be demanded before using the private key
        /// </summary>
        private static KeyContainerPermission BuildKeyContainerPermission(CngKey key, KeyContainerPermissionFlags flags)
        {
            // If this isn't a named key, then we can use it without any demand
            if (key.IsEphemeral || String.IsNullOrEmpty(key.KeyName))
            {
                return null;
            }

            KeyContainerPermissionAccessEntry entry = new KeyContainerPermissionAccessEntry(key.KeyName, flags);
            entry.ProviderName = key.Provider.Provider;

            KeyContainerPermission permission = new KeyContainerPermission(PermissionState.None);
            permission.AccessEntries.Add(entry);
            return permission;
        }

        /// <summary>
        ///     Create an object to hash signature data with
        /// </summary>
        private HashAlgorithm CreateSignatureHashObject()
        {
            if (m_signatureHashAlgorithm == CngAlgorithm.MD5)
            {
                return new MD5Cng();
            }
            else if (m_signatureHashAlgorithm == CngAlgorithm.Sha1)
            {
                return new SHA1Cng();
            }
            else if (m_signatureHashAlgorithm == CngAlgorithm.Sha256)
            {
                return new SHA256Cng();
            }
            else if (m_signatureHashAlgorithm == CngAlgorithm.Sha384)
            {
                return new SHA384Cng();
            }
            else if (m_signatureHashAlgorithm == CngAlgorithm.Sha512)
            {
                return new SHA512Cng();
            }
            else
            {
                throw new InvalidOperationException("InvalidSignatureHashAlgorithm");
            }
        }

        //
        // Key import and export
        //

        /// <summary>
        ///     Exports the key used by the RSA object into an RSAParameters object.
        /// </summary>
        /// <permission cref="KeyContainerPermission">
        ///      If the includePrivateParameters parameter is true and the CngKey is not ephemeral,
        ///      KeyContainerPermission will be demanded.
        /// </permission>
        [SecurityCritical]
        [SecuritySafeCritical]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Safe use of SizeOf")]
        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            byte[] rsaBlob = Key.Export(includePrivateParameters ? s_rsaFullPrivateBlob : s_rsaPublicBlob);
            RSAParameters rsaParams = new RSAParameters();

            //
            // We now have a buffer laid out as follows:
            //     BCRYPT_RSAKEY_BLOB   header
            //     byte[cbPublicExp]    publicExponent      - Exponent
            //     byte[cbModulus]      modulus             - Modulus
            //     -- Private only --
            //     byte[cbPrime1]       prime1              - P
            //     byte[cbPrime2]       prime2              - Q
            //     byte[cbPrime1]       exponent1           - DP
            //     byte[cbPrime2]       exponent2           - DQ
            //     byte[cbPrime1]       coefficient         - InverseQ
            //     byte[cbModulus]      privateExponent     - D
            //

            unsafe
            {
                fixed (byte* pRsaBlob = rsaBlob)
                {
                    BCryptNative.BCRYPT_RSAKEY_BLOB* pBcryptBlob = (BCryptNative.BCRYPT_RSAKEY_BLOB*)pRsaBlob;
                    
                    int offset = Marshal.SizeOf(typeof(BCryptNative.BCRYPT_RSAKEY_BLOB));

                    // Read out the exponent
                    rsaParams.Exponent = new byte[pBcryptBlob->cbPublicExp];
                    Buffer.BlockCopy(rsaBlob, offset, rsaParams.Exponent, 0, rsaParams.Exponent.Length);
                    offset += pBcryptBlob->cbPublicExp;

                    // Read out the modulus
                    rsaParams.Modulus = new byte[pBcryptBlob->cbModulus];
                    Buffer.BlockCopy(rsaBlob, offset, rsaParams.Modulus, 0, rsaParams.Modulus.Length);
                    offset += pBcryptBlob->cbModulus;

                    if (includePrivateParameters)
                    {
                        // Read out P
                        rsaParams.P = new byte[pBcryptBlob->cbPrime1];
                        Buffer.BlockCopy(rsaBlob, offset, rsaParams.P, 0, rsaParams.P.Length);
                        offset += pBcryptBlob->cbPrime1;

                        // Read out Q
                        rsaParams.Q = new byte[pBcryptBlob->cbPrime2];
                        Buffer.BlockCopy(rsaBlob, offset, rsaParams.Q, 0, rsaParams.Q.Length);
                        offset += pBcryptBlob->cbPrime2;

                        // Read out DP
                        rsaParams.DP = new byte[pBcryptBlob->cbPrime1];
                        Buffer.BlockCopy(rsaBlob, offset, rsaParams.DP, 0, rsaParams.DP.Length);
                        offset += pBcryptBlob->cbPrime1;

                        // Read out DQ
                        rsaParams.DQ = new byte[pBcryptBlob->cbPrime2];
                        Buffer.BlockCopy(rsaBlob, offset, rsaParams.DQ, 0, rsaParams.DQ.Length);
                        offset += pBcryptBlob->cbPrime2;

                        // Read out InverseQ
                        rsaParams.InverseQ = new byte[pBcryptBlob->cbPrime1];
                        Buffer.BlockCopy(rsaBlob, offset, rsaParams.InverseQ, 0, rsaParams.InverseQ.Length);
                        offset += pBcryptBlob->cbPrime1;

                        //  Read out D
                        rsaParams.D = new byte[pBcryptBlob->cbModulus];
                        Buffer.BlockCopy(rsaBlob, offset, rsaParams.D, 0, rsaParams.D.Length);
                        offset += pBcryptBlob->cbModulus;
                    }
                }
            }

            return rsaParams;
        }

        /// <summary>
        ///     <para>
        ///         ImportParameters will replace the existing key that RSACng is working with by creating a
        ///         new CngKey for the parameters structure. If the parameters structure contains only an
        ///         exponent and modulus, then only a public key will be imported. If the parameters also
        ///         contain P and Q values, then a full key pair will be imported.
        ///     </para>
        ///     <para>
        ///         The default KSP used by RSACng does not support importing full RSA key pairs on Windows
        ///         Vista. If the ImportParameters method is called with a full key pair, the operation will
        ///         fail with a CryptographicException stating that the operation was invalid. Other KSPs may
        ///         have similar restrictions. To work around this, make sure to only import public keys when
        ///         using the default KSP.
        ///     </para>
        /// </summary>
        /// <exception cref="ArgumentException">
        ///     if <paramref name="parameters" /> contains neither an exponent nor a modulus
        /// </exception>
        /// <exception cref="CryptographicException">
        ///     if <paramref name="parameters" /> is not a valid RSA key or if <paramref name="parameters"
        ///     /> is a full key pair and the default KSP is used
        /// </exception>
        [SecurityCritical]
        [SecuritySafeCritical]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Safe use of SizeOf")]
        public override void ImportParameters(RSAParameters parameters)
        {
            if (parameters.Exponent == null || parameters.Modulus == null)
                throw new ArgumentException("InvalidRsaParameters");

            bool publicOnly = parameters.P == null || parameters.Q == null;

            //
            // We need to build a key blob structured as follows:
            //     BCRYPT_RSAKEY_BLOB   header
            //     byte[cbPublicExp]    publicExponent      - Exponent
            //     byte[cbModulus]      modulus             - Modulus
            //     -- Private only --
            //     byte[cbPrime1]       prime1              - P
            //     byte[cbPrime2]       prime2              - Q
            //

            int blobSize = Marshal.SizeOf(typeof(BCryptNative.BCRYPT_RSAKEY_BLOB)) +
                           parameters.Exponent.Length +
                           parameters.Modulus.Length;
            if (!publicOnly)
            {
                blobSize += parameters.P.Length +
                            parameters.Q.Length;
            }

            byte[] rsaBlob = new byte[blobSize];
            unsafe
            {
                fixed (byte* pRsaBlob = rsaBlob)
                {
                    // Build the header
                    BCryptNative.BCRYPT_RSAKEY_BLOB* pBcryptBlob = (BCryptNative.BCRYPT_RSAKEY_BLOB*)pRsaBlob;
                    pBcryptBlob->Magic = publicOnly ? BCryptNative.KeyBlobMagicNumber.RsaPublic :
                                                      BCryptNative.KeyBlobMagicNumber.RsaPrivate;

                    pBcryptBlob->BitLength = parameters.Modulus.Length * 8;

                    pBcryptBlob->cbPublicExp = parameters.Exponent.Length;
                    pBcryptBlob->cbModulus = parameters.Modulus.Length;

                    if (!publicOnly)
                    {
                        pBcryptBlob->cbPrime1 = parameters.P.Length;
                        pBcryptBlob->cbPrime2 = parameters.Q.Length;
                    }

                    int offset = Marshal.SizeOf(typeof(BCryptNative.BCRYPT_RSAKEY_BLOB));

                    // Copy the exponent
                    Buffer.BlockCopy(parameters.Exponent, 0, rsaBlob, offset, parameters.Exponent.Length);
                    offset += parameters.Exponent.Length;

                    // Copy the modulus
                    Buffer.BlockCopy(parameters.Modulus, 0, rsaBlob, offset, parameters.Modulus.Length);
                    offset += parameters.Modulus.Length;

                    if (!publicOnly)
                    {
                        // Copy P
                        Buffer.BlockCopy(parameters.P, 0, rsaBlob, offset, parameters.P.Length);
                        offset += parameters.P.Length;

                        // Copy Q
                        Buffer.BlockCopy(parameters.Q, 0, rsaBlob, offset, parameters.Q.Length);
                        offset += parameters.Q.Length;
                    }
                }
            }

            // CngKey.Import will demand KeyContainerPermission since it doesn't know if the RSA blobs contain
            // an embedded key container name or not.  Since we built the blob ourselves, we know that we
            // didn't specify a key container, so we can assert that demand away.
            new KeyContainerPermission(KeyContainerPermissionFlags.Import).Assert();
            Key = CngKey.Import(rsaBlob, publicOnly ? s_rsaPublicBlob : s_rsaPrivateBlob);
            CodeAccessPermission.RevertAssert();
        }

        //
        // Encryption and decryption
        //

        /// <summary>
        ///     DecryptValue decrypts the input data using the padding mode specified in the
        ///     EncryptionPaddingMode property. The return value is the decrypted data.
        /// </summary>
        /// <param name="rgb">encrypted data to decrypt</param>
        /// <exception cref="ArgumentNullException">if <paramref name="rgb" /> is null</exception>
        /// <exception cref="CryptographicException">if <paramref name="rgb" /> could not be decrypted</exception>
        /// <permission cref="KeyContainerPermission">
        ///      This method requires KeyContainerPermission to the key in use if it is not ephemeral.
        /// </permission>
        [SecurityCritical]
        [SecuritySafeCritical]
        public override byte[] DecryptValue(byte[] rgb)
        {
            if (rgb == null)
                throw new ArgumentNullException("rgb");

            // Keep a local copy of the key to prevent races with the key container that the key references
            // and the key container permission we're going to demand.
            CngKey key = Key;

            // Make sure we have permission to use the private key to decrypt data
            KeyContainerPermission kcp = BuildKeyContainerPermission(key, KeyContainerPermissionFlags.Decrypt);
            if (kcp != null)
            {
                kcp.Demand();
            }

            new SecurityPermission(SecurityPermissionFlag.UnmanagedCode).Assert();
            SafeNCryptKeyHandle keyHandle = key.Handle;
            CodeAccessPermission.RevertAssert();

            switch (EncryptionPaddingMode)
            {
                case AsymmetricPaddingMode.Pkcs1:
                    return NCryptNative.DecryptDataPkcs1(keyHandle, rgb);
                case AsymmetricPaddingMode.Oaep:
                    return NCryptNative.DecryptDataOaep(keyHandle, rgb, EncryptionHashAlgorithm.Algorithm);

                default:
                    throw new InvalidOperationException("UnsupportedPaddingMode");
            };
        }

        /// <summary>
        ///     EncryptValue encrypts the input data using the padding mode specified in the
        ///     EncryptionPaddingMode property. The return value is the encrypted data.
        /// </summary>
        /// <param name="rgb">data to encrypt</param>
        /// <exception cref="ArgumentNullException">if <paramref name="rgb" /> is null</exception>
        /// <exception cref="CryptographicException">if <paramref name="rgb" /> could not be decrypted</exception>
        [SecurityCritical]
        [SecuritySafeCritical]
        public override byte[] EncryptValue(byte[] rgb)
        {
            if (rgb == null)
                throw new ArgumentNullException("rgb");

            switch (EncryptionPaddingMode)
            {
                case AsymmetricPaddingMode.Pkcs1:
                    return NCryptNative.EncryptDataPkcs1(KeyHandle, rgb);
                case AsymmetricPaddingMode.Oaep:
                    return NCryptNative.EncryptDataOaep(KeyHandle, rgb, EncryptionHashAlgorithm.Algorithm);

                default:
                    throw new InvalidOperationException("UnsupportedPaddingMode");
            };
        }

        //
        // Signature APIs
        //

        /// <summary>
        ///     SignData signs the given data after hashing it with the SignatureHashAlgorithm algorithm.
        /// </summary>
        /// <param name="data">data to sign</param>
        /// <exception cref="ArgumentNullException">if <paramref name="data" /> is null</exception>
        /// <exception cref="CryptographicException">if <paramref name="data" /> could not be signed</exception>
        /// <exception cref="InvalidOperationException">
        ///     if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512
        /// </exception>
        /// <permission cref="KeyContainerPermission">
        ///      This method will demand KeyContainerPermission if the key being used is not ephemeral.
        /// </permission>
        public byte[] SignData(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            return SignData(data, 0, data.Length);
        }

        /// <summary>
        ///     SignData signs the given data after hashing it with the SignatureHashAlgorithm algorithm.
        /// </summary>
        /// <param name="data">data to sign</param>
        /// <param name="offset">offset into the data that the signature should begin covering</param>
        /// <param name="count">number of bytes to include in the signed data</param>
        /// <exception cref="ArgumentNullException">if <paramref name="data" /> is null</exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     if <paramref name="offset" /> or <paramref name="count" /> are negative, or if
        ///     <paramref name="count" /> specifies more bytes than are available in <paramref name="data" />.
        /// </exception>
        /// <exception cref="CryptographicException">if <paramref name="data" /> could not be signed</exception>
        /// <exception cref="InvalidOperationException">
        ///     if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512
        /// </exception>
        /// <permission cref="KeyContainerPermission">
        ///      This method will demand KeyContainerPermission if the key being used is not ephemeral.
        /// </permission>
        public byte[] SignData(byte[] data, int offset, int count)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            if (offset < 0)
                throw new ArgumentOutOfRangeException("offset");
            if (count < 0)
                throw new ArgumentOutOfRangeException("count");
            if (count > data.Length - offset)
                throw new ArgumentOutOfRangeException("count");

            using (HashAlgorithm hashObject = CreateSignatureHashObject())
            {
                byte[] hashedData = hashObject.ComputeHash(data, offset, count);
                return SignHash(hashedData);
            }
        }

        /// <summary>
        ///     SignData signs the given data after hashing it with the SignatureHashAlgorithm algorithm.
        /// </summary>
        /// <param name="data">data to sign</param>
        /// <exception cref="ArgumentNullException">if <paramref name="data" /> is null</exception>
        /// <exception cref="CryptographicException">if <paramref name="data" /> could not be signed</exception>
        /// <exception cref="InvalidOperationException">
        ///     if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512
        /// </exception>
        /// <permission cref="KeyContainerPermission">
        ///      This method will demand KeyContainerPermission if the key being used is not ephemeral.
        /// </permission>
        public byte[] SignData(Stream data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            using (HashAlgorithm hashObject = CreateSignatureHashObject())
            {
                byte[] hashedData = hashObject.ComputeHash(data);
                return SignHash(hashedData);
            }
        }

        /// <summary>
        ///     Sign data which was hashed using the SignatureHashAlgorithm; if the algorithm used to hash
        ///     the data was different, use the SignHash(byte[], CngAlgorithm) overload instead.
        /// </summary>
        /// <param name="hash">hash to sign</param>
        /// <exception cref="ArgumentNullException">if <paramref name="hash" /> is null</exception>
        /// <exception cref="CryptographicException">if <paramref name="hash" /> could not be signed</exception>
        /// <exception cref="InvalidOperationException">
        ///     if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512
        /// </exception>
        /// <permission cref="KeyContainerPermission">
        ///      This method will demand KeyContainerPermission if the key being used is not ephemeral.
        /// </permission>
        public byte[] SignHash(byte[] hash)
        {
            return SignHash(hash, SignatureHashAlgorithm);
        }

        /// <summary>
        ///     Sign already hashed data, specifying the algorithm it was hashed with.  This method does not
        ///     use the SignatureHashAlgorithm property.
        /// </summary>
        /// <param name="hash">hash to sign</param>
        /// <param name="hashAlgorithm">algorithm <paramref name="hash" /> was signed with</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="hash" /> or <paramref name="hashAlgorithm"/> are null
        ///  </exception>
        /// <exception cref="CryptographicException">if <paramref name="hash" /> could not be signed</exception>
        /// <permission cref="KeyContainerPermission">
        ///      This method will demand KeyContainerPermission if the key being used is not ephemeral.
        /// </permission>
        [SecurityCritical]
        [SecuritySafeCritical]
        public byte[] SignHash(byte[] hash, CngAlgorithm hashAlgorithm)
        {
            if (hash == null)
                throw new ArgumentNullException("hash");
            if (hashAlgorithm == null)
                throw new ArgumentNullException("hashAlgorithm");

            // Keep a local copy of the key to prevent races with the key container that the key references
            // and the key container permission we're going to demand.
            CngKey key = Key;

            KeyContainerPermission kcp = BuildKeyContainerPermission(key, KeyContainerPermissionFlags.Sign);
            if (kcp != null)
            {
                kcp.Demand();
            }

            new SecurityPermission(SecurityPermissionFlag.UnmanagedCode).Assert();
            SafeNCryptKeyHandle keyHandle = key.Handle;
            CodeAccessPermission.RevertAssert();

            switch (SignaturePaddingMode)
            {
                case AsymmetricPaddingMode.Pkcs1:
                    return NCryptNative.SignHashPkcs1(keyHandle, hash, hashAlgorithm.Algorithm);
                case AsymmetricPaddingMode.Pss:
                    return NCryptNative.SignHashPss(keyHandle, hash, hashAlgorithm.Algorithm, SignatureSaltBytes);

                default:
                    throw new InvalidOperationException("UnsupportedPaddingMode");
            }
        }

        //
        // Signature verification APIs
        //

        /// <summary>
        ///     VerifyData verifies that the given signature matches given data after hashing it with the
        ///     SignatureHashAlgorithm algorithm.
        /// </summary>
        /// <param name="data">data to verify</param>
        /// <param name="signature">signature of the data</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="data" /> or <paramref name="signature" /> are null
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///     if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512
        /// </exception>
        /// <returns>true if the signature verifies for the data, false if it does not</returns>
        public bool VerifyData(byte[] data, byte[] signature)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            return VerifyData(data, 0, data.Length, signature);
        }

        /// <summary>
        ///     VerifyData verifies that the given signature matches given data after hashing it with the
        ///     SignatureHashAlgorithm algorithm.
        /// </summary>
        /// <param name="data">data to verify</param>
        /// <param name="offset">offset into the data that the signature should begin covering</param>
        /// <param name="count">number of bytes to include in the signed data</param>
        /// <param name="signature">signature of the data</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="data" /> or <paramref name="signature" /> are null
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     if <paramref name="offset" /> or <paramref name="count" /> are negative, or if
        ///     <paramref name="count" /> specifies more bytes than are available in <paramref name="data" />.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///     if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512
        /// </exception>
        /// <returns>true if the signature verifies for the data, false if it does not</returns>
        public bool VerifyData(byte[] data, int offset, int count, byte[] signature)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            if (offset < 0)
                throw new ArgumentOutOfRangeException("offset");
            if (count < 0)
                throw new ArgumentOutOfRangeException("count");
            if (count > data.Length - offset)
                throw new ArgumentOutOfRangeException("count");
            if (signature == null)
                throw new ArgumentNullException("signature");

            using (HashAlgorithm hashObject = CreateSignatureHashObject())
            {
                byte[] hashedData = hashObject.ComputeHash(data, offset, count);
                return VerifyHash(hashedData, signature);
            }
        }

        /// <summary>
        ///     VerifyData verifies that the given signature matches given data after hashing it with the
        ///     SignatureHashAlgorithm algorithm.
        /// </summary>
        /// <param name="data">data to verify</param>
        /// <param name="signature">signature of the data</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="data" /> or <paramref name="signature" /> are null
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///     if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512
        /// </exception>
        /// <returns>true if the signature verifies for the data, false if it does not</returns>
        public bool VerifyData(Stream data, byte[] signature)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            if (signature == null)
                throw new ArgumentNullException("signature");

            using (HashAlgorithm hashObject = CreateSignatureHashObject())
            {
                byte[] hashedData = hashObject.ComputeHash(data);
                return VerifyHash(hashedData, signature);
            }
        }

        /// <summary>
        ///     Verify data which was signed and already hashed with the SignatureHashAlgorithm; if a
        ///     different hash algorithm was used to hash the data use the VerifyHash(byte[], byte[],
        ///     CngAlgorithm) overload instead.
        /// </summary>
        /// <param name="hash">hash to verify</param>
        /// <param name="signature">signature of the data</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="hash" /> or <paramref name="signature" /> are null
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///     if SignatureHashAlgorithm is not MD5, SHA-1, SHA-256, SHA-384, or SHA-512
        /// </exception>
        /// <returns>true if the signature verifies for the hash, false if it does not</returns>
        public bool VerifyHash(byte[] hash, byte[] signature)
        {
            return VerifyHash(hash, signature, SignatureHashAlgorithm);
        }

        /// <summary>
        ///     Verify data which was signed and hashed with the given hash algorithm.  This overload does
        ///     not use the SignatureHashAlgorithm property.
        /// </summary>
        /// <param name="hash">hash to verify</param>
        /// <param name="signature">signature of the data</param>
        /// <param name="hashAlgorithm">algorithm that <paramref name="hash" /> was hashed with</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="hash" />, <paramref name="signature" />, or
        ///     <paramref name="hashAlgorithm" /> are null
        /// </exception>
        /// <returns>true if the signature verifies for the hash, false if it does not</returns>
        [SecurityCritical]
        [SecuritySafeCritical]
        public bool VerifyHash(byte[] hash, byte[] signature, CngAlgorithm hashAlgorithm)
        {
            if (hash == null)
                throw new ArgumentNullException("hash");
            if (signature == null)
                throw new ArgumentNullException("signature");
            if (hashAlgorithm == null)
                throw new ArgumentNullException("hashAlgorithm");

            switch (SignaturePaddingMode)
            {
                case AsymmetricPaddingMode.Pkcs1:
                    return NCryptNative.VerifySignaturePkcs1(KeyHandle, hash, hashAlgorithm.Algorithm, signature);
                case AsymmetricPaddingMode.Pss:
                    return NCryptNative.VerifySignaturePss(KeyHandle, hash, hashAlgorithm.Algorithm, SignatureSaltBytes, signature);

                default:
                    throw new InvalidOperationException("UnsupportedPaddingMode");
            }
        }
    }
}
