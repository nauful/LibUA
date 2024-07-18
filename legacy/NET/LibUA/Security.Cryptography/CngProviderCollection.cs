// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     <para>
    ///         The CngProviderCollection class implements an enumerator over the installed CNG providers on
    ///         the machine. The enumerator specifically lists the NCrypt key storage providers, and does not
    ///         work with the BCrypt layer of CNG.
    ///     </para>
    ///     <para>
    ///         CngProviderCollection uses the NCrypt layer of CNG to do its work, and requires Windows Vista
    ///         and the .NET Framework 3.5.
    ///     </para>
    /// </summary>
    public sealed class CngProviderCollection : IEnumerable<CngProvider>
    {
        /// <summary>
        ///     Get an enumerator containing a <see cref="CngProvider" /> for each of the installed NCrypt
        ///     key storage providers on the current machine.
        /// </summary>
        public IEnumerator<CngProvider> GetEnumerator()
        {
            foreach (NCryptNative.NCryptProviderName providerName in NCryptNative.EnumerateStorageProviders())
            {
                yield return new CngProvider(providerName.pszName);
            }
        }

        /// <summary>
        ///     Get an enumerator containing a <see cref="CngProvider" /> for each of the installed NCrypt
        ///     key storage providers on the current machine.
        /// </summary>
        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}
