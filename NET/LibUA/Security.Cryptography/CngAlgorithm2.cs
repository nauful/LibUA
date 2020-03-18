// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     The CngAlgorithm2 class provides additional <see cref="CngAlgorithm" /> objects to suppliment the
    ///     ones found on the standard <see cref="CngAlgorithm" /> type.
    /// </summary>
    public static class CngAlgorithm2
    {
        private static CngAlgorithm s_aes;
        private static CngAlgorithm s_rsa;

        /// <summary>
        ///     CngAlgorithm for the AES symmetric algorithm
        /// </summary>
        public static CngAlgorithm Aes
        {
            get
            {
                if (s_aes == null)
                {
                    s_aes = new CngAlgorithm(BCryptNative.AlgorithmName.Aes);
                }

                return s_aes;
            }
        }

        /// <summary>
        ///     CngAlgorithm for the RSA asymmetric algorithm
        /// </summary>
        public static CngAlgorithm Rsa
        {
            get
            {
                if (s_rsa == null)
                {
                    s_rsa = new CngAlgorithm(BCryptNative.AlgorithmName.Rsa);
                }

                return s_rsa;
            }
        }
    }
}
