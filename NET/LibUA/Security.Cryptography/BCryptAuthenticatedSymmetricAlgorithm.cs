// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Security;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     Generic implementation of an authenticated symmetric algorithm which is provided by the BCrypt
    ///     layer of CNG.  Concrete AuthenticatedSymmetricAlgorithm classes should contain an instance of this
    ///     type and delegate all of their work to that object.
    ///     
    ///     Most of the real encryption work occurs in the BCryptAuthenticatedCryptoTransform class. (see
    ///     code:code:Microsoft.Security.Cryptography.BCryptAuthenticatedSymmetricCryptoTransform).
    /// </summary>
    internal sealed class BCryptAuthenticatedSymmetricAlgorithm : AuthenticatedSymmetricAlgorithm, ICngSymmetricAlgorithm
    {
        private readonly CngAlgorithm m_algorithm;
        private CngChainingMode m_chainingMode;
        private readonly CngProvider m_implementation;

        [SecurityCritical]
        [SecuritySafeCritical]
        internal BCryptAuthenticatedSymmetricAlgorithm(CngAlgorithm algorithm,
                                                       CngProvider implementation,
                                                       KeySizes[] legalBlockSizes,
                                                       KeySizes[] legalKeySizes)
        {
            Debug.Assert(algorithm != null, "algorithm != null");
            Debug.Assert(implementation != null, "implementation != null");
            Debug.Assert(legalBlockSizes != null, "legalBlockSizes != null");
            Debug.Assert(legalKeySizes != null, "legalKeySizes != null");

            m_algorithm = algorithm;
            m_implementation = implementation;
            m_chainingMode = CngChainingMode.Gcm;

            LegalBlockSizesValue = legalBlockSizes;
            LegalKeySizesValue = legalKeySizes;

            // Create a temporary algorithm handle so that we can query it for some properties - such as the
            // block and tag sizes.
            using (SafeBCryptAlgorithmHandle algorithmHandle = SetupAlgorithm())
            {
                // Get block size in bits
                BlockSize = BCryptNative.GetInt32Property(algorithmHandle, BCryptNative.ObjectPropertyName.BlockLength) * 8;

                UpdateLegalTagSizes(algorithmHandle);
            }
        }

        /// <summary>
        ///     Determine if the current mode supports calculating the authenticated cipher across multiple
        ///     transform calls, or must the entire cipher be calculated at once.
        /// </summary>
        public bool ChainingSupported
        {
            get
            {
                // Currently only CCM does not support chaining.
                return m_chainingMode != CngChainingMode.Ccm;
            }
        }

        /// <summary>
        ///     Chaining mode to use for chaining in the authenticated algorithm.  This value should be one
        ///     of the CNG modes that is an authenticated chaining mode such as CCM or GCM.
        /// </summary>
        public CngChainingMode CngMode
        {
            get { return m_chainingMode; }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                // Updating the chaining mode requires doing other work, such as figuring out the new set of
                // legal tag sizes.  If we're just setting to the same value we already were in, then don't
                // bother changing the value.
                if (m_chainingMode != value)
                {
                    // Don't do a direct check for GCM or CCM since we want to allow expansion to future
                    // authenticated chaining modes.
                    m_chainingMode = value;

                    // Legal tag sizes vary with chaining mode, so we need to update them when we update the
                    // chaining mode.  Preserve the existing tag in case it's still legal in the new mode.
                    byte[] tag = Tag;
                    try
                    {
                        UpdateLegalTagSizes();

                        // If the old tag is still of a legal tag size, restore it as the new tag now.
                        if (ValidTagSize(tag.Length * 8))
                        {
                            Tag = tag;
                        }
                    }
                    finally
                    {
                        Array.Clear(tag, 0, tag.Length);
                    }
                }
            }
        }

        /// <summary>
        ///     Algorithm provider which is implementing the authenticated transform
        /// </summary>
        public CngProvider Provider
        {
            get { return m_implementation; }
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        public override IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor(byte[] rgbKey,
                                                                                   byte[] rgbIV,
                                                                                   byte[] rgbAuthenticatedData)
        {
            return new BCryptAuthenticatedSymmetricCryptoTransform(SetupAlgorithm(),
                                                                   rgbKey,
                                                                   rgbIV,
                                                                   rgbAuthenticatedData,
                                                                   ChainingSupported,
                                                                   TagSize);
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey,
                                                         byte[] rgbIV,
                                                         byte[] rgbAuthenticatedData,
                                                         byte[] rgbTag)
        {
            if (rgbKey == null)
                throw new ArgumentNullException("rgbKey");
            if (rgbTag == null)
                throw new ArgumentNullException("rgbTag");

            return new BCryptAuthenticatedSymmetricCryptoTransform(SetupAlgorithm(),
                                                                   rgbKey,
                                                                   rgbIV,
                                                                   rgbAuthenticatedData,
                                                                   rgbTag,
                                                                   ChainingSupported);
        }

        /// <summary>
        ///     Build an algorithm handle setup according to the parameters of this AES object
        /// </summary>
        [SecurityCritical]
        private SafeBCryptAlgorithmHandle SetupAlgorithm()
        {
            // Open the algorithm handle
            SafeBCryptAlgorithmHandle algorithm =
                BCryptNative.OpenAlgorithm(m_algorithm.Algorithm, m_implementation.Provider);

            // Set the chaining mode
            BCryptNative.SetStringProperty(algorithm,
                                           BCryptNative.ObjectPropertyName.ChainingMode,
                                           m_chainingMode.ChainingMode);

            return algorithm;
        }

        public override void GenerateIV()
        {
            // Both GCM and CCM work well with 12 byte nonces, so use that by default.
            IVValue = RNGCng.GenerateKey(12);
        }

        public override void GenerateKey()
        {
            KeyValue = RNGCng.GenerateKey(KeySizeValue / 8);
        }

        /// <summary>
        ///     Update the legal tag sizes for this algorithm
        /// </summary>
        [SecurityCritical]
        [SecuritySafeCritical]
        private void UpdateLegalTagSizes()
        {
            using (SafeBCryptAlgorithmHandle algorithm = SetupAlgorithm())
            {
                UpdateLegalTagSizes(algorithm);
            }
        }

        /// <summary>
        ///     Update the legal tag sizes for this algortithm from an already opened algorithm handle
        /// </summary>
        [SecurityCritical]
        private void UpdateLegalTagSizes(SafeBCryptAlgorithmHandle algorithm)
        {
            Debug.Assert(algorithm != null, "algorithm != null");
            Debug.Assert(!algorithm.IsClosed && !algorithm.IsInvalid, "!algorithm.IsClosed && !algorithm.IsInvalid");

            // Get the authentication tag length structure.
            BCryptNative.BCRYPT_KEY_LENGTHS_STRUCT tagLengths =
                BCryptNative.GetValueTypeProperty<SafeBCryptAlgorithmHandle, BCryptNative.BCRYPT_KEY_LENGTHS_STRUCT>(
                    algorithm,
                    BCryptNative.ObjectPropertyName.AuthTagLength);

            // BCrypt returns the tag sizes in bytes, convert them to bits for the LegalTagSizes property
            LegalTagSizesValue = new KeySizes[]
            {
                new KeySizes(tagLengths.dwMinLength * 8, tagLengths.dwMaxLength * 8, tagLengths.dwIncrement * 8)
            };

            // By default, generate the maximum authentication tag length possible for this algorithm
            TagSize = tagLengths.dwMaxLength * 8;
        }
    }
}
