// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    //
    // Public facing enumerations
    //

    /// <summary>
    ///     The OidGroup enumeration has values for each of the built in Windows groups that OIDs can be
    ///     categorized into.
    /// </summary>
    public enum OidGroup
    {
        /// <summary>
        ///     When used for searching for or enumerating over OIDs, specifies that the search or enumeration
        ///     should include OIDs found in all of the groups. 
        /// </summary>
        AllGroups                           = 0,

        /// <summary>
        ///     A group for OIDs that represent hashing algortihms.  This maps to the native
        ///     CRYPT_HASH_ALG_OID_GROUP_ID group.
        /// </summary>
        HashAlgorithm                       = 1,

        /// <summary>
        ///     A group for OIDs that represent symmetric encryption algorithms.  This maps to the native
        ///     CRYPT_ENCRYPT_ALG_OID_GROUP_ID group.
        /// </summary>
        EncryptionAlgorithm                 = 2,

        /// <summary>
        ///     A group for OIDs that represent asymmetric encryption algorithms.  This maps to the native
        ///     CRYPT_PUBKEY_ALG_OID_GROUP_ID group.
        /// </summary>
        PublicKeyAlgorithm                  = 3,

        /// <summary>
        ///     A group for OIDs that represent digital signature algorithms.  This maps to the native
        ///     CRYPT_SIGN_ALG_OID_GROUP_ID group.
        /// </summary>
        SignatureAlgorithm                  = 4,

        /// <summary>
        ///     A group for OIDs that represent RDN attributes.  This maps to the native
        ///     CRYPT_RDN_ATTR_OID_GROUP_ID group.
        /// </summary>
        Attribute                           = 5,

        /// <summary>
        ///     A group for OIDs that represent X.509 certificate extensions or attributes.  This maps to
        ///     the native CRYPT_EXT_OR_ATTR_OID_GROUP_ID group.
        /// </summary>
        ExtensionOrAttribute                = 6,

        /// <summary>
        ///     A group for OIDs that represent X.509 certificate enhanced key usages.  This maps to the
        ///     native CRYPT_ENHKEY_USAGE_OID_GROUP_ID group.
        /// </summary>
        EnhancedKeyUsage                    = 7,

        /// <summary>
        ///     A group for OIDs that represent policies.  This maps to the native CRYPT_POLICY_OID_GROUP_ID
        ///     group.
        /// </summary>
        Policy                              = 8,

        /// <summary>
        ///     A group for OIDs that represent templates.  This maps to the native
        ///     CRYPT_TEMPLATE_OID_GROUP_ID group.
        /// </summary>
        Template                            = 9,


        /// <summary>
        ///     A group for OIDS that represent key derivation algorithms.  This maps to the native
        ///     CRYPT_KDF_OID_GROUP_ID group.
        /// </summary>
        KeyDerivationFunction               = 10,
    }

    /// <summary>
    ///     The OidRegistrationOptions enumeration has flags used to control how a new OID is registered on
    ///     the machine with the <see cref="Oid2.Register(OidRegistrationOptions)" /> API.
    /// </summary>
    [Flags]
    public enum OidRegistrationOptions
    {
        /// <summary>
        ///     The OID is installed after the built in OIDs
        /// </summary>
        None                                = 0x00000000,

        /// <summary>
        ///     The OID is installed before the built in OIDs.  This maps to the native
        ///     CRYPT_INSTALL_OID_INFO_BEFORE_FLAG option.
        /// </summary>
        InstallBeforeDefaultEntries         = 0x00000001,
    }

    /// <summary>
    ///     Native wrappers for CAPI APIs.
    ///     
    ///     The general pattern for this interop layer is that the CapiNative type exports a wrapper method
    ///     for consumers of the interop methods.  This wrapper method puts a managed face on the raw
    ///     P/Invokes, by translating from native structures to managed types and converting from error
    ///     codes to exceptions.
    ///     
    ///     The native definitions here are generally found in wincrypt.h
    /// </summary>
    internal static class CapiNative
    {
        //
        // Enumerations
        //

        /// <summary>
        ///     Class fields for CAPI algorithm identifiers
        /// </summary>
        internal enum AlgorithmClass
        {
            Any         = (0 << 13),                    // ALG_CLASS_ANY
            Hash        = (4 << 13),                    // ALG_CLASS_HASH
        }

        /// <summary>
        ///     Type identifier fields for CAPI algorithm identifiers
        /// </summary>
        internal enum AlgorithmType
        {
            Any         = (0 << 9),                     // ALG_TYPE_ANY
        }

        /// <summary>
        ///     Sub identifiers for CAPI algorithm identifiers
        /// </summary>
        internal enum AlgorithmSubId
        {
            Any         = 0,                            // ALG_SID_ANY
            Sha256      = 12,                           // ALG_SID_SHA_256
            Sha384      = 13,                           // ALG_SID_SHA_384
            Sha512      = 14,                           // ALG_SID_SHA_512

        }

        /// <summary>
        ///     CAPI algorithm identifiers
        /// </summary>
        internal enum AlgorithmID
        {
            None = 0,

            Sha256 =                    (AlgorithmClass.Hash                | AlgorithmType.Any             | AlgorithmSubId.Sha256),                   // CALG_SHA_256
            Sha384 =                    (AlgorithmClass.Hash                | AlgorithmType.Any             | AlgorithmSubId.Sha384),                   // CALG_SHA_384
            Sha512 =                    (AlgorithmClass.Hash                | AlgorithmType.Any             | AlgorithmSubId.Sha512),                   // CALG_SHA_512
        }

        internal enum OidKeyType
        {
            Oid                                 = 1,            // CRYPT_OID_INFO_OID_KEY
            Name                                = 2,            // CRYPT_OID_INFO_NAME_KEY
            AlgoritmID                          = 3,            // CRYPT_OID_INFO_ALGID_KEY
            SignatureAlgorithm                  = 4,            // CRYPT_OID_INFO_SIGN_KEY
            CngAlgorithmId                      = 5,            // CRYPT_OID_INFO_CNG_ALGID_KEY
            CngSignatureAlgorithm               = 6,            // CRYPT_OID_INFO_CNG_SIGN_KEY
        }

        internal static class WellKnownOids
        {
            // Algorithm OIDS
            internal static string ECDsaSha1    = "1.2.840.10045.4.1";          // szOID_ECDSA_SHA1
            internal static string ECDsaSha256  = "1.2.840.10045.4.3.2";        // szOID_ECDSA_SHA256
            internal static string ECDsaSha384  = "1.2.840.10045.4.3.3";        // szOID_ECDSA_SHA384
            internal static string ECDsaSha512  = "1.2.840.10045.4.3.4";        // szOID_ECDSA_SHA512
            internal static string RsaSha1      = "1.2.840.113549.1.1.5";       // szOID_RSA_SHA1RSA
            internal static string RsaSha256    = "1.2.840.113549.1.1.11";      // szOID_RSA_SHA256RSA
            internal static string RsaSha384    = "1.2.840.113549.1.1.12";      // szOID_RSA_SHA384RSA
            internal static string RsaSha512    = "1.2.840.113549.1.1.13";      // szOID_RSA_SHA512RSA
            internal static string Sha256       = "2.16.840.1.101.3.4.2.1";     // szOID_NIST_sha256
            internal static string Sha384       = "2.16.840.1.101.3.4.2.2";     // szOID_NIST_sha384
            internal static string Sha512       = "2.16.840.1.101.3.4.2.3";     // szOID_NIST_sha512

            // X509 certificate extension OIDS
            internal static string SubjectAlternateName     = "2.5.29.7";       // szOID_SUBJECT_ALT_NAME
            internal static string IssuerAlternateName      = "2.5.29.8";       // szOID_ISSUER_ALT_NAME
            internal static string SubjectAlternateName2    = "2.5.29.17";      // szOID_SUBJECT_ALT_NAME2
            internal static string IssuerAlternateName2     = "2.5.29.18";      // szOID_ISSUER_ALT_NAME2
        }

        //
        // Structures
        //

        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPT_ALGORITHM_IDENTIFIER
        {
            [MarshalAs(UnmanagedType.LPStr)]
            internal string pszObjId;

            internal CRYPTOAPI_BLOB Parameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPT_BIT_BLOB
        {
            internal int cbData;
            internal IntPtr pbData; // byte *
            internal int cUnusedBits;
        }

        // Current CRYPT_OID_INFO structure
        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPT_OID_INFO
        {
            internal int cbSize;

            [MarshalAs(UnmanagedType.LPStr)]
            internal string pszOID;

            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszName;

            internal OidGroup dwGroupId;

            // Really a union of dwValue, dwLength, or ALG_ID Algid
            internal int dwValue;

            internal CRYPTOAPI_BLOB ExtraInfo;

            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszCNGAlgid;

            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszCNGExtraAlgid;
        }

        // CRYPT_OID_INFO as it was on Windows 2003 and earlier
        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPT_OID_INFO_WIN2K3
        {
            internal int cbSize;

            [MarshalAs(UnmanagedType.LPStr)]
            internal string pszOID;

            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszName;

            internal OidGroup dwGroupId;

            // Really a union of dwValue, dwLength, or ALG_ID Algid
            internal int dwValue;

            internal CRYPTOAPI_BLOB ExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        [SuppressMessage("Microsoft.Design", "CA1049:TypesThatOwnNativeResourcesShouldBeDisposable", Justification = "CRYPTOAPI_BLOB does not own any resources")]
        internal struct CRYPTOAPI_BLOB
        {
            internal int cbData;

            [SuppressMessage("Microsoft.Reliability", "CA2006:UseSafeHandleToEncapsulateNativeResources", Justification = "This field is for a byte *, not for a handle, and is cleaned up differently depending upon how the byte * was allocated")]
            internal IntPtr pbData; // BYTE*
        }

        //
        // P/Invokes
        // 

        [SuppressUnmanagedCodeSecurity]
        private static class UnsafeNativeMethods
        {
            // CryptEnumOIDInfo for Vista and later
            [DllImport("crypt32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CryptEnumOIDInfo(OidGroup dwGroupId,
                                                         int dwFlags,
                                                         IntPtr pvArg,
                                                         CryptEnumOidInfoCallback pfnEnumOIDInfo);

            // CryptEnumOIDInfo for Windows 2003 and earlier
            [DllImport("crypt32.dll", EntryPoint = "CryptEnumOIDInfo")]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CryptEnumOIDInfoWin2k3(OidGroup dwGroupId,
                                                               int dwFlags,
                                                               IntPtr pvArg,
                                                               CryptEnumOidInfoCallbackWin2k3 pfnEnumOIDInfo);
                                                         
            [DllImport("crypt32.dll")]
            internal static extern IntPtr CryptFindOIDInfo(OidKeyType dwKeyType,
                                                           IntPtr pvKey,
                                                           OidGroup dwGroupId);

            [DllImport("crypt32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CryptRegisterOIDInfo([In] ref CRYPT_OID_INFO pInfo,
                                                             OidRegistrationOptions dwFlags);

            [DllImport("crypt32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CryptUnregisterOIDInfo([In] ref CRYPT_OID_INFO pInfo);
        }

        //
        // Delegates
        //

        // CryptEnumOIDInfo callback for Vista and later
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private delegate bool CryptEnumOidInfoCallback([In] ref CRYPT_OID_INFO pInfo, IntPtr pvArg);

        // CryptEnumOIDInfo callback for Windows 2003 and earlier
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private delegate bool CryptEnumOidInfoCallbackWin2k3([In] ref CRYPT_OID_INFO_WIN2K3 pInfo, IntPtr pvArg);

        //
        // Wrapper APIs
        //

        /// <summary>
        ///     The size of an OID structure grew between Windows 2003 and Windows Vista.  This property
        ///     detects which version of the OS we are on and which version of the structure to use. 
        ///     (CRYPT_OID_INFO_WIN2K3 for pre-Vista and CRYPT_OID_INFO for Vista or later).
        /// </summary>
        private static bool UseWin2k3OidStructures
        {
            get
            {
                return Environment.OSVersion.Platform == PlatformID.Win32NT &&
                       (Environment.OSVersion.Version.Major < 5 ||
                        (Environment.OSVersion.Version.Major == 5 && Environment.OSVersion.Version.Minor <= 2));
            }
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        [SuppressMessage("Microsoft.Reliability", "CA2004:RemoveCallsToGCKeepAlive", Justification = "This is keeping a managed delegate alive, not a native resource")]
        internal static CRYPT_OID_INFO[] EnumerateOidInformation(OidGroup group)
        {
            // This list is passed through to the callbacks as a GCHandle, so if the type of this object is
            // changed, the type expected in OidEnumerationCallback must also be changed.
            List<CRYPT_OID_INFO> oidInformation = new List<CRYPT_OID_INFO>();

            GCHandle oidInformationHandle = new GCHandle();

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                // Get a handle to the OID information list so that we can pass it into the callback function
                oidInformationHandle = GCHandle.Alloc(oidInformation, GCHandleType.Normal);

                if (!UseWin2k3OidStructures)
                {
                    CryptEnumOidInfoCallback callback = new CryptEnumOidInfoCallback(OidEnumerationCallback);

                    UnsafeNativeMethods.CryptEnumOIDInfo(group,
                                                         0,
                                                         GCHandle.ToIntPtr(oidInformationHandle),
                                                         callback);

                    // Make sure we don't GC the callback delegate before we're done enumerating
                    GC.KeepAlive(callback);
                }
                else
                {
                    CryptEnumOidInfoCallbackWin2k3 callback = new CryptEnumOidInfoCallbackWin2k3(OidEnumerationCallbackWin2k3);

                    UnsafeNativeMethods.CryptEnumOIDInfoWin2k3(group,
                                                               0,
                                                               GCHandle.ToIntPtr(oidInformationHandle),
                                                               callback);

                    // Make sure we don't GC the callback delegate before we're done enumerating
                    GC.KeepAlive(callback);
                }
            }
            finally
            {
                if (oidInformationHandle.IsAllocated)
                {
                    oidInformationHandle.Free();
                }
            }

            return oidInformation.ToArray();
        }

        /// <summary>
        ///     Read a CAPI blob into a managed byte array
        /// </summary>
        [SecurityCritical]
        internal static byte[] ReadBlob(CRYPTOAPI_BLOB capiBlob)
        {
            byte[] managedBlob = new byte[capiBlob.cbData];

            unsafe
            {
                byte* pCapiBlob = (byte*)capiBlob.pbData.ToPointer();
                for (int i = 0; i < managedBlob.Length; ++i)
                {
                    managedBlob[i] = pCapiBlob[i];
                }
            }

            return managedBlob;
        }

        /// <summary>
        ///     Register a new OID on the machine
        /// </summary>
        [SecurityCritical]
        internal static void RegisterOid(CRYPT_OID_INFO oidInfo, OidRegistrationOptions registrationOptions)
        {
            if (!UnsafeNativeMethods.CryptRegisterOIDInfo(ref oidInfo, registrationOptions))
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }
        }

        /// <summary>
        ///     OID enumeration callback for Windows 
        /// </summary>
        [SecurityCritical]
        private static bool OidEnumerationCallback(ref CRYPT_OID_INFO oid, IntPtr oidInformationPointer)
        {
            Debug.Assert(oidInformationPointer != IntPtr.Zero, "oidInformationPointer != IntPtr.Zero");

            GCHandle oidInformationHandle = GCHandle.FromIntPtr(oidInformationPointer);
            List<CRYPT_OID_INFO> oidInformation = oidInformationHandle.Target as List<CRYPT_OID_INFO>;
            Debug.Assert(oidInformation != null, "Unexpected type in oidInformationPointer GC Handle");

            oidInformation.Add(oid);
            return true;
        }

        /// <summary>
        ///     OID enumeration callback for Windows 2003 and earlier
        /// </summary>
        [SecurityCritical]
        private static bool OidEnumerationCallbackWin2k3(ref CRYPT_OID_INFO_WIN2K3 oid, IntPtr oidInformationPointer)
        {
            CRYPT_OID_INFO fullOid = UpgradeOidInfo(oid);
            return OidEnumerationCallback(ref fullOid, oidInformationPointer);
        }

        /// <summary>
        ///     Find an OID based upon a string key
        /// </summary>
        [SecurityCritical]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Safe exposure of LinkDemands via security critical method")]
        internal static bool TryFindOidInfo(string key,
                                            OidGroup group,
                                            OidKeyType keyType,
                                            bool lookupInActiveDirectory,
                                            out CRYPT_OID_INFO oidInfo)
        {
            Debug.Assert(!String.IsNullOrEmpty(key), "!String.IsNullOrEmpty(key)");

            IntPtr keyPointer = IntPtr.Zero;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                // Setting the CRYPT_OID_DISABLE_SEARCH_DS_FLAG (0x80000000) in the group type suppresses
                // the network lookup of the OID information.  We or the bit in directly, since it's not a
                // real group type, and we don't want to mix it into the enumeration itself
                if (!lookupInActiveDirectory)
                {
                    group = (OidGroup)((uint)group | 0x80000000);
                }

                // Convert the key into a native representation based upon search type
                if (keyType == OidKeyType.Oid)
                {
                    keyPointer = Marshal.StringToCoTaskMemAnsi(key);
                }
                else if (keyType == OidKeyType.Name ||
                         keyType == OidKeyType.CngAlgorithmId)
                {
                    keyPointer = Marshal.StringToCoTaskMemUni(key);
                }
                else
                {
                    Debug.Assert(false, "Unsupported key type");
                }
                IntPtr oid =  UnsafeNativeMethods.CryptFindOIDInfo(keyType, keyPointer, group);

                // Do the search, and if we succeeded, marshal the data back to the caller.  The
                // CRYPT_OID_INFO being pointed to by the result of the search should not be freed by us
                // because it is owned by CAPI.
                if (oid != IntPtr.Zero)
                {
                    if (!UseWin2k3OidStructures)
                    {
                        oidInfo = (CRYPT_OID_INFO)Marshal.PtrToStructure(oid, typeof(CRYPT_OID_INFO));
                    }
                    else
                    {
                        oidInfo = UpgradeOidInfo((CRYPT_OID_INFO_WIN2K3)Marshal.PtrToStructure(oid, typeof(CRYPT_OID_INFO_WIN2K3)));
                    }

                    return true;
                }
                else
                {
                    // Did not find the OID
                    oidInfo = new CRYPT_OID_INFO();
                    return false;
                }
            }
            finally
            {
                if (keyPointer != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(keyPointer);
                }
            }
        }

        /// <summary>
        ///     Remove an OID from the machine registration
        /// </summary>
        [SecurityCritical]
        internal static void UnregisterOid(CRYPT_OID_INFO oid)
        {
            if (!UnsafeNativeMethods.CryptUnregisterOIDInfo(ref oid))
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }
        }

        /// <summary>
        ///     Convert an older Win2k3 sized OID info structure into a full OID info structure
        /// </summary>
        [SecurityCritical]
        [SecuritySafeCritical]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Safe use of Marshal.SizeOf")]
        private static CRYPT_OID_INFO UpgradeOidInfo(CRYPT_OID_INFO_WIN2K3 oldOid)
        {
            return new CRYPT_OID_INFO
            {
                cbSize = Marshal.SizeOf(typeof(CRYPT_OID_INFO)),
                pszOID = oldOid.pszOID,
                pwszName = oldOid.pwszName,
                dwGroupId = oldOid.dwGroupId,
                dwValue = oldOid.dwValue,
                ExtraInfo = oldOid.ExtraInfo,
                pwszCNGAlgid = null,
                pwszCNGExtraAlgid = null
            };
        }
    }
}
