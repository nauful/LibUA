// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     <para>
    ///         The AuthenticatedSymmetricAlgorithm abstract base class forms the base class for symmetric
    ///         algorithms which support authentication as well as encryption. Authenticated symmetric
    ///         algorithms produce an authentication tag in addition to ciphertext, which allows data to be
    ///         both authenticated and protected for privacy. For instance, AES with CCM or GCM chaining modes
    ///         provides authentication, and therefore derive from AuthenticatedSymmetricAlgorithm.
    ///    </para>
    ///    <para>
    ///         AuthenticatedSymmetricAlgorithm derives from <see cref="SymmetricAlgorithm" />, so all of the
    ///         SymmetricAlgorithm APIs also apply to AuthenticatedSymmericAlgorithm objects.
    ///     </para>
    /// </summary>
    public abstract class AuthenticatedSymmetricAlgorithm : SymmetricAlgorithm
    {
        private byte[] m_authenticatedData;
        private byte[] m_tag;

        //
        // Tag size values - these are protected fields without array copy semantics to behave similar to
        // the KeySize / IVSize mechanisms
        //

        /// <summary>
        ///     The LegalTagSizes field is set by authenticated symmetric algorithm implementations to be the
        ///     set of valid authentication tag sizes expressed in bits.
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1051:DoNotDeclareVisibleInstanceFields", Justification = "Consistency with other SymmetricAlgorithm APIs (LegalKeySizesValue, LegalBlockSizesValue")]
        protected KeySizes[] LegalTagSizesValue;

        /// <summary>
        ///     The TagSizeValue field contains the current authentication tag size used by the authenticated
        ///     symmetric algorithm, expressed in bits.
        /// </summary>
        [SuppressMessage("Microsoft.Design", "CA1051:DoNotDeclareVisibleInstanceFields", Justification = "Consistency with other SymmetricAlgorithm APIs (KeyValue, BlockValue, etc)")]
        protected int TagSizeValue;

        /// <summary>
        ///     <para>
        ///         Gets or sets the authenticated data buffer.
        ///     </para>
        ///     <para>
        ///         This data is included in calculations of the authentication tag, but is not included in
        ///         the ciphertext.  A value of null means that there is no additional authenticated data.
        ///     </para>
        /// </summary>
        [SuppressMessage("Microsoft.Performance", "CA1819:PropertiesShouldNotReturnArrays", Justification = "Consistency with the other SymmetricAlgorithm API (Key, IV, etc)")]
        public virtual byte[] AuthenticatedData
        {
            get
            {
                return m_authenticatedData != null ? m_authenticatedData.Clone() as byte[] : null;
            }

            set
            {
                if (value != null)
                {
                    m_authenticatedData = value.Clone() as byte[];
                }
                else
                {
                    m_authenticatedData = null;
                }
            }
        }

        /// <summary>
        ///     Get or set the IV (nonce) to use with transorms created with this object.
        /// </summary>
        /// <exception cref="ArgumentNullException">if set to null</exception>
        public override byte[] IV
        {
            // Note that we override the base implementation because it requires that the nonce equal the
            // block size, while in general authenticated transforms do not.

            get
            {
                if (IVValue == null)
                {
                    GenerateIV();
                }

                return IVValue.Clone() as byte[];
            }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                IVValue = value.Clone() as byte[];
            }
        }

        /// <summary>
        ///     Gets the ranges of legal sizes for authentication tags produced by this algorithm, expressed
        ///     in bits.
        /// </summary>
        [SuppressMessage("Microsoft.Performance", "CA1819:PropertiesShouldNotReturnArrays", Justification = "Consistency with other SymmetricAlgorithm APIs (LegalKeySizes, LegalBlockSizes)")]
        public virtual KeySizes[] LegalTagSizes
        {
            get { return LegalTagSizesValue.Clone() as KeySizes[]; }
        }

        /// <summary>
        ///     Gets or sets the authentication tag to use when verifying a decryption operation.  This
        ///     value is only read for decryption operaions, and is not used for encryption operations.  To
        ///     find the value of the tag generated on encryption, check the Tag property of the
        ///     IAuthenticatedCryptoTransform encryptor object.
        /// </summary>
        /// <exception cref="ArgumentNullException">if the tag is set to null</exception>
        /// <exception cref="ArgumentException">if the tag is not a legal size</exception>
        [SuppressMessage("Microsoft.Performance", "CA1819:PropertiesShouldNotReturnArrays", Justification = "Consistency with other SymmetricAlgorithm APIs (Key, IV)")]
        public virtual byte[] Tag
        {
            get
            {
                if (m_tag == null)
                {
                    m_tag = new byte[TagSizeValue / 8];
                }

                return m_tag.Clone() as byte[];
            }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");
                if (!ValidTagSize(value.Length * 8))
                    throw new ArgumentException("InvalidTagSize", "value");

                m_tag = value.Clone() as byte[];
                TagSizeValue = m_tag.Length * 8;
            }
        }

        /// <summary>
        ///     Get or set the size (in bits) of the authentication tag
        /// </summary>
        /// <exception cref="ArgumentException">if the value is not a legal tag size</exception>
        public virtual int TagSize
        {
            get { return TagSizeValue; }

            set
            {
                if (!ValidTagSize(value))
                    throw new ArgumentOutOfRangeException("InvalidTagSize");

                TagSizeValue = value;
                m_tag = null;
            }
        }

        /// <summary>
        ///     Creates an instance of the default AuthenticatedSymmetricAlgorithm registered in
        ///     <see cref="CryptoConfig2" />. By default, this is the <see cref="AuthenticatedAesCng" />
        ///      algorithm.
        /// </summary>
        public static new AuthenticatedSymmetricAlgorithm Create()
        {
            return Create(typeof(AuthenticatedSymmetricAlgorithm).Name);
        }

        /// <summary>
        ///     Create an instance of the specified AuthenticatedSymmetricAlgorithm type. If the type cannot
        ///     be found in <see cref="CryptoConfig2" />, Create returns null.
        /// </summary>
        /// <param name="algorithm">name of the authenticated symmetric algorithm to create</param>
        /// <exception cref="ArgumentNullException">if <paramref name="algorithm"/> is null</exception>
        public static new AuthenticatedSymmetricAlgorithm Create(string algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");

            return CryptoConfig2.CreateFromName(algorithm) as AuthenticatedSymmetricAlgorithm;
        }

        /// <summary>
        ///     Create an authenticated encryptor using the key, nonce, and authenticated data from the
        ///     properties of this algorithm object.
        /// </summary>
        public virtual IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor()
        {
            return CreateAuthenticatedEncryptor(Key, IV, AuthenticatedData);
        }

        /// <summary>
        ///     Create an authenticated encryptor using the specified key and nonce, and using the
        ///     authenticated data from the property of this algorithm object.
        /// </summary>
        /// <param name="rgbKey">key to use for the encryption operation</param>
        /// <param name="rgbIV">nonce to use for the encryption operation</param>
        public virtual IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return CreateAuthenticatedEncryptor(rgbKey, rgbIV, AuthenticatedData);
        }

        /// <summary>
        ///     Create an authenticated encryptor using the specified key, nonce, and authenticated data.
        /// </summary>
        /// <param name="rgbKey">key to use for the encryption operation</param>
        /// <param name="rgbIV">nonce to use for the encryption operation</param>
        /// <param name="rgbAuthenticatedData">optional extra authenticated data to use for the encryption operation</param>
        public abstract IAuthenticatedCryptoTransform CreateAuthenticatedEncryptor(byte[] rgbKey,
                                                                                   byte[] rgbIV,
                                                                                   byte[] rgbAuthenticatedData);

        /// <summary>
        ///     Create a decryptor using the key, nonce, authenticated data, and authentication tag from the
        ///     properties of this algorithm object.
        /// </summary>
        public override ICryptoTransform CreateDecryptor()
        {
            return CreateDecryptor(Key, IV, AuthenticatedData, Tag);
        }

        /// <summary>
        ///     Create a decryptor with the given key and nonce, using the authenticated data and
        ///     authentication tag from the properties of the algorithm object.
        /// </summary>
        /// <param name="rgbKey">key to use for the decryption operation</param>
        /// <param name="rgbIV">nonce to use for the decryption operation</param>
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return CreateDecryptor(rgbKey, rgbIV, AuthenticatedData, Tag);
        }

        /// <summary>
        ///     Create a decryption transform with the given key, nonce, authenticated data, and
        ///     authentication tag.
        /// </summary>
        /// <param name="rgbKey">key to use for the decryption operation</param>
        /// <param name="rgbIV">nonce to use for the decryption operation</param>
        /// <param name="rgbAuthenticatedData">optional extra authenticated data to use for the decryption operation</param>
        /// <param name="rgbTag">authenticated tag to verify while decrypting</param>
        public abstract ICryptoTransform CreateDecryptor(byte[] rgbKey,
                                                         byte[] rgbIV,
                                                         byte[] rgbAuthenticatedData,
                                                         byte[] rgbTag);

        /// <summary>
        ///     Create an encryptor using the given key and nonce, and the authenticated data from this
        ///     algorithm.
        /// </summary>
        public override ICryptoTransform CreateEncryptor()
        {
            return CreateAuthenticatedEncryptor();
        }

        /// <summary>
        ///     Create an encryptor using the given key and nonce, and the authenticated data from this
        ///     algorithm.
        /// </summary>
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return CreateAuthenticatedEncryptor(rgbKey, rgbIV);
        }

        /// <summary>
        ///     Determine if an authentication tag size (in bits) is valid for use with this algorithm.
        /// </summary>
        /// <param name="tagSize">authentication tag size in bits to check</param>
        public bool ValidTagSize(int tagSize)
        {
            // If we don't have any valid tag sizes, then no tag is of the correct size
            if (LegalTagSizes == null)
            {
                return false;
            }

            // Loop over all of the legal size ranges, and see if we match any of them
            foreach (KeySizes legalTagSizeRange in LegalTagSizes)
            {
                for (int legalTagSize = legalTagSizeRange.MinSize;
                     legalTagSize <= legalTagSizeRange.MaxSize;
                     legalTagSize += legalTagSizeRange.SkipSize)
                {
                    if (legalTagSize == tagSize)
                    {
                        return true;
                    }
                }
            }

            // No matches - this isn't a valid tag size
            return false;
        }
    }
}
