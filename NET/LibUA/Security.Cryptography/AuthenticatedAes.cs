// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     The AuthenticatedAes abstract base class forms the base class for concrete implementations of
    ///     authenticated AES algorithms. For instance, AES with CCM or GCM chaining modes provides
    ///     authentication, and therefore derive from AuthenticatedAes.
    /// </summary>
    public abstract class AuthenticatedAes : AuthenticatedSymmetricAlgorithm
    {
        private static readonly KeySizes[] s_legalBlockSizes = { new KeySizes(128, 128, 0) };
        private static readonly KeySizes[] s_legalKeySizes = { new KeySizes(128, 256, 64) };

        protected AuthenticatedAes()
        {
            LegalBlockSizesValue = s_legalBlockSizes;
            LegalKeySizesValue = s_legalKeySizes;

            BlockSizeValue = 128;
            KeySizeValue = 256;
        }

        /// <summary>
        ///     Creates an instance of the default AuthenticatedAes registered in <see cref="CryptoConfig2" />.
        ///     By default, this is the <see cref="AuthenticatedAesCng" /> algorithm.
        /// </summary>
        public static new AuthenticatedAes Create()
        {
            return Create(typeof(AuthenticatedAes).Name);
        }

        /// <summary>
        ///     Create an instance of the specified AuthenticatedAes type. If the type cannot be found in
        ///     <see cref="CryptoConfig2" />, Create returns null.
        /// </summary>
        /// <param name="algorithm">name of the authenticated symmetric algorithm to create</param>
        /// <exception cref="ArgumentNullException">if <paramref name="algorithm"/> is null</exception>
        public static new AuthenticatedAes Create(string algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");

            return CryptoConfig2.CreateFromName(algorithm) as AuthenticatedAes;
        }
    }
}
