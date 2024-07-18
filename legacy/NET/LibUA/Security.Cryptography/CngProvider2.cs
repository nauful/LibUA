// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     The CngProvider2 class provides additional <see cref="CngProvider" /> objects to suppliment the
    ///     ones found on the standard <see cref="CngProvider" /> type.
    /// </summary>
    public static class CngProvider2
    {
        private static CngProvider s_primitiveAlgorithmProvider;

        /// <summary>
        ///     Get a CngProvider for the Microsoft Primitive algorithm provider
        /// </summary>
        public static CngProvider MicrosoftPrimitiveAlgorithmProvider
        {
            get
            {
                if (s_primitiveAlgorithmProvider == null)
                {
                    s_primitiveAlgorithmProvider = new CngProvider(BCryptNative.ProviderName.MicrosoftPrimitiveProvider);
                }

                return s_primitiveAlgorithmProvider;
            }
        }
    }
}
