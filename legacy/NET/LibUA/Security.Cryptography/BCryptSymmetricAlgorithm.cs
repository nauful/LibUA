// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Security;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     Generic implementation of a symmetric algorithm which is provided by the BCrypt layer of CNG.
    ///     Concrete SymmetricAlgorithm classes should contain an instance of this type and delegate all of
    ///     their work to that object.
    ///     
    ///     Most of the real encryption work occurs in the BCryptSymmetricCryptoTransform class. (see
    ///     code:code:Microsoft.Security.Cryptography.BCryptSymmetricCryptoTransform).
    /// </summary>
    internal sealed class BCryptSymmetricAlgorithm : SymmetricAlgorithm, ICngSymmetricAlgorithm
    {
        private readonly CngAlgorithm m_algorithm;
        private readonly CngProvider m_algorithmProvider;
        private CngChainingMode m_chainingMode;

        internal BCryptSymmetricAlgorithm(CngAlgorithm algorithm,
                                          CngProvider algorithmProvider,
                                          KeySizes[] legalBlockSizes,
                                          KeySizes[] legalkeySizes)
        {
            Debug.Assert(algorithm != null, "algorithm != null");
            Debug.Assert(algorithmProvider != null, "algorithmProvider != null");
            Debug.Assert(legalBlockSizes != null, "legalBlockSizes != null");
            Debug.Assert(legalkeySizes != null, "legalKeySizes != null");

            m_algorithm = algorithm;
            m_algorithmProvider = algorithmProvider;

            LegalBlockSizesValue = legalBlockSizes;
            LegalKeySizesValue = legalkeySizes;
        }

        /// <summary>
        ///     Setup a BCrypt algorithm with our current parameters
        /// </summary>
        [SecurityCritical]
        [SecuritySafeCritical]
        private SafeBCryptAlgorithmHandle SetupAlgorithm()
        {
            SafeBCryptAlgorithmHandle algorithmHandle = BCryptNative.OpenAlgorithm(m_algorithm.Algorithm, m_algorithmProvider.Provider);

            // If we've selected a different block size than the default, set that now
            if (BlockSize / 8 != BCryptNative.GetInt32Property(algorithmHandle, BCryptNative.ObjectPropertyName.BlockLength))
            {
                BCryptNative.SetInt32Property(algorithmHandle, BCryptNative.ObjectPropertyName.BlockLength, BlockSize / 8);
            }

            BCryptNative.SetStringProperty(algorithmHandle, BCryptNative.ObjectPropertyName.ChainingMode, m_chainingMode.ChainingMode);

            return algorithmHandle;
        }

        //
        // ICngSymmetricAlgorithm implementation
        //

        public CngChainingMode CngMode
        {
            get { return m_chainingMode; }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                m_chainingMode = value;
            }
        }

        public override CipherMode Mode
        {
            get
            {
                return BCryptNative.MapChainingMode(m_chainingMode.ChainingMode);
            }

            set
            {
                m_chainingMode = new CngChainingMode(BCryptNative.MapChainingMode(value));
            }
        }

        public CngProvider Provider
        {
            get { return m_algorithmProvider; }
        }

        //
        // SymmetricAlgorithm abstract method implementations
        //

        [SecurityCritical]
        [SecuritySafeCritical]
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            if (rgbKey == null)
                throw new ArgumentNullException("rgbKey");

            return new BCryptSymmetricCryptoTransform(SetupAlgorithm(), rgbKey, rgbIV, Padding, false);
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            if (rgbKey == null)
                throw new ArgumentNullException("rgbKey");

            return new BCryptSymmetricCryptoTransform(SetupAlgorithm(), rgbKey, rgbIV, Padding, true);
        }

        public override void GenerateIV()
        {
            IVValue = RNGCng.GenerateKey(BlockSizeValue / 8);
        }

        public override void GenerateKey()
        {
            KeyValue = RNGCng.GenerateKey(KeySizeValue / 8);
        }
    }
}
