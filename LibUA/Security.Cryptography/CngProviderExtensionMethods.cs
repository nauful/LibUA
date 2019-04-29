// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security;
using System.Security.Permissions;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     <para>
    ///         The CngProviderExtensionMethods type provides several extension methods for the
    ///         <see cref="CngProvider" /> class.  This type is in the Security.Cryptography namespace (not
    ///         the System.Security.Cryptography namespace), so in order to use these extension methods, you
    ///         will need to make sure you include this namespace as well as a reference to
    ///         Security.Cryptography.dll
    ///     </para>
    ///     <para>
    ///         CngProvider uses the NCrypt layer of CNG, and requires Windows Vista and the .NET Framework
    ///         3.5.
    ///     </para>
    /// </summary>
    public static class CngProviderExtensionMethods
    {
        /// <summary>
        ///     GetKeys provides an enumerator over all of the keys that are stored in the key storage
        ///     provider.
        /// </summary>
        public static IEnumerable<CngKey> GetKeys(this CngProvider provider)
        {
            foreach (CngKey machineKey in GetKeys(provider, CngKeyOpenOptions.MachineKey))
            {
                yield return machineKey;
            }

            foreach (CngKey userKey in GetKeys(provider, CngKeyOpenOptions.UserKey))
            {
                yield return userKey;
            }
        }

        /// <summary>
        ///     GetKeys provides an enumerator over all of the keys that are stored in the key storage
        ///     provider. This overload of GetKeys allows you to enumerate over only the user keys in the
        ///     KSP or only the machine keys.
        /// </summary>
        /// <param name="provider">CngProvider to enumerate the keys of</param>
        /// <param name="openOptions">options to use when opening the CNG keys</param>
        [SecurityCritical]
        [SecuritySafeCritical]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Safe use of OpenProvider")]
        public static IEnumerable<CngKey> GetKeys(this CngProvider provider, CngKeyOpenOptions openOptions)
        {
            using (SafeNCryptProviderHandle providerHandle = provider.OpenProvider())
            {
                NCryptNative.NCryptKeyName[] keyNames = NCryptNative.EnumerateKeys(providerHandle, openOptions);
                CngKey[] keys = new CngKey[keyNames.Length];

                for (int i = 0; i < keys.Length; ++i)
                {
                    keys[i] = CngKey.Open(keyNames[i].pszName, provider);
                }

                return keys;
            }
        }

        /// <summary>
        ///     GetKeys provides an enumerator over all of the keys that are stored in the key storage
        ///     provider. This overload of GetKeys allows you to enumerate over only the user keys in the KSP
        ///     or only the machine keys. It also allows you to return only keys that are usable with a
        ///     specified algorithm.
        /// </summary>
        /// <param name="provider">CngProvider to enumerate the keys of</param>
        /// <param name="openOptions">options to use when opening the CNG keys</param>
        /// <param name="algorithm">algorithm that the returned keys should support</param>
        /// <exception cref="ArgumentNullException">if <paramref name="algorithm" /> is null</exception>
        public static IEnumerable<CngKey> GetKeys(this CngProvider provider,
                                                  CngKeyOpenOptions openOptions,
                                                  CngAlgorithm algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");

            return from key in provider.GetKeys(openOptions)
                   where key.Algorithm == algorithm
                   select key;
        }

        /// <summary>
        ///     GetSupportedAlgorithms provides an enumerator over all of the algorithms that the NCrypt
        ///     provider supports.
        /// </summary>
        public static IEnumerable<CngAlgorithm> GetSupportedAlgorithms(this CngProvider provider)
        {
            return GetSupportedAlgorithms(provider, NCryptAlgorithmOperations.AsymmetricEncryption |
                                                    NCryptAlgorithmOperations.Cipher |
                                                    NCryptAlgorithmOperations.Hash |
                                                    NCryptAlgorithmOperations.RandomNumberGeneration |
                                                    NCryptAlgorithmOperations.SecretAgreement |
                                                    NCryptAlgorithmOperations.Signature);
        }

        /// <summary>
        ///     GetSupportedAlgorithms provides an enumerator over all of the algorithms that the NCrypt
        ///     provider supports. Each of the returned algortihms will support at least one of the
        ///     cryptographic operations specified by the operations parameter.
        /// </summary>
        /// <param name="provider">CngProvider to enumerate the supported algorithms of</param>
        /// <param name="operations">operations that the returned algorithms should support</param>
        [SecurityCritical]
        [SecuritySafeCritical]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Safe exposure of OpenProvider")] 
        public static IEnumerable<CngAlgorithm> GetSupportedAlgorithms(this CngProvider provider,
                                                                       NCryptAlgorithmOperations operations)
        {
            using (SafeNCryptProviderHandle providerHandle = provider.OpenProvider())
            {
                NCryptNative.NCryptAlgorithmName[] algorithmNames = NCryptNative.EnumerateAlgorithms(providerHandle, operations);
                CngAlgorithm[] algorithms = new CngAlgorithm[algorithmNames.Length];

                for (int i = 0; i < algorithmNames.Length; ++i)
                {
                    algorithms[i] = new CngAlgorithm(algorithmNames[i].pszName);
                }

                return algorithms;
            }
        }

        /// <summary>
        ///     Gets a SafeHandle for the NCrypt provider. This handle can be used for P/Invoking to other
        ///     APIs which expect an NCRYPT_PROV_HANDLE parameter.
        /// </summary>
        /// <permission cref="SecurityPermission">
        ///     SecurityPermission/UnmanagedCode is required of the immediate caller to this API
        /// </permission>
        [SecurityCritical]
        [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
        public static SafeNCryptProviderHandle OpenProvider(this CngProvider provider)
        {
            return NCryptNative.OpenKeyStorageProvider(provider.Provider);
        }
    }
}