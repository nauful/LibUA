// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

namespace LibUA.Security.Cryptography.X509Certificates
{
    //
    // Public facing enumerations
    //

    /// <summary>
    ///     Types of alternate names that can be applied to an X509 certificate
    /// </summary>
    public enum AlternateNameType
    {
        None = 0,

        /// <summary>
        ///     Alternate name that isn't one of the standard alternate name types.  This corresponds to the
        ///     CERT_ALT_NAME_OTHER_NAME type.
        /// </summary>
        OtherName = 1,

        /// <summary>
        ///     Alternate name represented as an email address as defined in RFC 822.  This corresponds to the
        ///     CERT_ALT_NAME_RFC822_NAME type.
        /// </summary>
        Rfc822Name = 2,

        /// <summary>
        ///     Alternate name represented as a DNS name.  This corresponds to the CERT_ALT_NAME_DNS_NAME type.
        /// </summary>
        DnsName = 3,

        /// <summary>
        ///     Alternate name represented as an x400 address.  This corresponds to the
        ///     CERT_ALT_NAME_X400_ADDRESS type.
        /// </summary>
        X400Address = 4,

        /// <summary>
        ///     Alternate name given as a directory name.  This corresponds to the
        ///     CERT_ALT_NAME_DIRECTORY_NAME type.
        /// </summary>
        DirectoryName = 5,

        /// <summary>
        ///     Alternate name given as an EDI party name.  This corresponds to the
        ///     CERT_ALT_NAME_EDI_PARTY_NAME type.
        /// </summary>
        EdiPartyName = 6,

        /// <summary>
        ///     Alternate URL.  This corresponds to the CERT_ALT_NAME_URL type.
        /// </summary>
        Url = 7,

        /// <summary>
        ///     Alternate name as an IP address.  This corresponds to the CERT_ALT_NAME_IP_ADDRESS type.
        /// </summary>
        IPAddress = 8,

        /// <summary>
        ///     Alternate name as a registered ID.  This corresponds to the CERT_ALT_NAME_REGISTERED_ID type.
        /// </summary>
        RegisteredId = 9,
    }

    /// <summary>
    ///     The X509CertificateCreationOptions enumeration provides a set of flags for use when creating a new
    ///     X509 certificate.
    /// </summary>
    [Flags]
    public enum X509CertificateCreationOptions
    {
        /// <summary>
        ///     Do not set any flags when creating the certificate
        /// </summary>
        None = 0x00000000,

        /// <summary>
        ///     Create an unsigned certificate.  This maps to the CERT_CREATE_SELFSIGN_NO_SIGN flag.
        /// </summary>
        DoNotSignCertificate = 0x00000001,

        /// <summary>
        ///     By default, certificates will reference their private keys by setting the
        ///     CERT_KEY_PROV_INFO_PROP_ID; the DoNotLinkKeyInformation flag causes the certificate to
        ///     instead contain the private key direclty rather than by reference.  This maps to the
        ///     CERT_CREATE_SELFSIGN_NO_KEY_INFO flag.
        /// </summary>
        DoNotLinkKeyInformation = 0x00000002,
    }

    /// <summary>
    ///     The X509CertificateSignatureAlgorithm enumeration provides a set of algorithms which can be used
    ///     to sign an X509 certificate.
    /// </summary>
    public enum X509CertificateSignatureAlgorithm
    {
        /// <summary>
        ///     The certificate is signed with RSA-SHA1
        /// </summary>
        RsaSha1,

        /// <summary>
        ///     The certificate is signed with RSA-SHA256
        /// </summary>
        RsaSha256,

        /// <summary>
        ///     The certificate is signed with RSA-SHA384
        /// </summary>
        RsaSha384,

        /// <summary>
        ///     The certificate is signed with RSA-SHA512
        /// </summary>
        RsaSha512,

        /// <summary>
        ///     The certificate is signed with ECDSA-SHA1
        /// </summary>
        ECDsaSha1,

        /// <summary>
        ///     The certificate is signed with ECDSA-SHA256
        /// </summary>
        ECDsaSha256,

        /// <summary>
        ///     The certificate is signed with ECDSA-SHA384
        /// </summary>
        ECDsaSha384,

        /// <summary>
        ///     The certificate is signed with ECDSA-SHA512
        /// </summary>
        ECDsaSha512,
    }

    /// <summary>
    ///     Native wrappers for X509 certificate APIs.
    ///     
    ///     The general pattern for this interop layer is that the X509Native type exports a wrapper method
    ///     for consumers of the interop methods.  This wrapper method puts a managed face on the raw
    ///     P/Invokes, by translating from native structures to managed types and converting from error
    ///     codes to exceptions.
    ///     
    ///     These APIs should strictly layer on top of the lower-level CNG and CAPI native APIs
    /// </summary>
    internal static class X509Native
    {
        //
        // Enumerations
        // 

        /// <summary>
        ///     Flags for the CryptAcquireCertificatePrivateKey API
        /// </summary>
        internal enum AcquireCertificateKeyOptions
        {
            None = 0x00000000,
            AcquireOnlyNCryptKeys = 0x00040000,   // CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG
        }

        /// <summary>
        ///     Flags indicating how a certificate is encoded
        /// </summary>
        [Flags]
        internal enum CertificateEncodingType
        {
            X509AsnEncoding = 0x00000001,       // X509_ASN_ENCODING
            Pkcs7AsnEncoding = 0x00010000,       // PKCS7_ASN_ENCODING
        }

        /// <summary>
        ///     Well known certificate property IDs
        /// </summary>
        internal enum CertificateProperty
        {
            KeyProviderInfo = 2,    // CERT_KEY_PROV_INFO_PROP_ID 
            KeyContext = 5,    // CERT_KEY_CONTEXT_PROP_ID
        }

        /// <summary>
        ///     Flags for the CertSetCertificateContextProperty API
        /// </summary>
        [Flags]
        internal enum CertificatePropertySetFlags
        {
            None = 0x00000000,
            NoCryptRelease = 0x00000001,   // CERT_STORE_NO_CRYPT_RELEASE_FLAG
        }

        /// <summary>
        ///     X509 version numbers
        /// </summary>
        internal enum CertificateVersion
        {
            Version1 = 0,    // CERT_V1
            Version2 = 1,    // CERT_V2
            Version3 = 2,    // CERT_V3
        }

        /// <summary>
        ///     Flags for the CryptDecodeObjectEx API
        /// </summary>
        [Flags]
        internal enum DecodeObjectFlags
        {
            None = 0x00000000,
            NoCopy = 0x00000001,       // CRYPT_DECODE_NOCOPY_FLAG
            ShareOidStrings = 0x00000004,       // CRYPT_DECODE_SHARE_OID_STRING_FLAG
            AllocateMemory = 0x00008000,       // CRYPT_DECODE_ALLOC_FLAG
        }

        /// <summary>
        ///     Error codes returned from X509 APIs
        /// </summary>
        internal enum ErrorCode
        {
            Success = 0x00000000,       // ERROR_SUCCESS
            MoreData = 0x000000ea,       // ERROR_MORE_DATA
        }

        /// <summary>
        ///     KeySpec for CERT_KEY_CONTEXT structures
        /// </summary>
        internal enum KeySpec
        {
            NCryptKey = unchecked((int)0xffffffff)    // CERT_NCRYPT_KEY_SPEC
        }

        //
        // Structures
        //

        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_ALT_NAME_ENTRY
        {
            internal AlternateNameType dwAltNameChoice;
            internal CERT_ALT_NAME_ENTRY_UNION altName;
        }

        [StructLayout(LayoutKind.Explicit)]
        internal struct CERT_ALT_NAME_ENTRY_UNION
        {
            [FieldOffset(0)]
            internal IntPtr pOtherName;     // PCERT_OTHER_NAME

            [FieldOffset(0)]
            internal IntPtr pwszRfc822Name; // LPWSTR

            [FieldOffset(0)]
            internal IntPtr pwszDNSName;    // LPWSTR

            [FieldOffset(0)]
            internal CapiNative.CRYPTOAPI_BLOB x400Address;

            [FieldOffset(0)]
            internal CapiNative.CRYPTOAPI_BLOB DirectoryName;

            [FieldOffset(0)]
            internal IntPtr pEdiPartyName;  // LPWSTR

            [FieldOffset(0)]
            internal IntPtr pwszURL;        // LPWSTR

            [FieldOffset(0)]
            internal CapiNative.CRYPTOAPI_BLOB IPAddress;

            [FieldOffset(0)]
            internal IntPtr pszRegisteredID;    // LPSTR
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_ALT_NAME_INFO
        {
            internal int cAltEntry;
            internal IntPtr rgAltEntry;     // CERT_ALT_ENTRY[cAltEntry]
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_CONTEXT
        {
            internal CertificateEncodingType dwCertEncodingType;
            internal IntPtr pbCertEncoded;      // byte *
            internal int cbCertEncoded;
            internal IntPtr pCertInfo;          // CERT_INFO *
            internal IntPtr hCertStore;         // HCERTSTORE
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_EXTENSION
        {
            [MarshalAs(UnmanagedType.LPStr)]
            internal string pszObjId;

            [MarshalAs(UnmanagedType.Bool)]
            internal bool fCritical;

            internal CapiNative.CRYPTOAPI_BLOB Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_EXTENSIONS
        {
            internal int cExtension;
            internal IntPtr rgExtension;                // CERT_EXTENSION[cExtension]
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_INFO
        {
            internal CertificateVersion dwVersion;
            internal CapiNative.CRYPTOAPI_BLOB SerialNumber;
            internal CapiNative.CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
            internal CapiNative.CRYPTOAPI_BLOB Issuer;
            internal FILETIME NotBefore;
            internal FILETIME NotAfter;
            internal CapiNative.CRYPTOAPI_BLOB Subject;
            internal CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
            internal CapiNative.CRYPT_BIT_BLOB IssuerUniqueId;
            internal CapiNative.CRYPT_BIT_BLOB SubjectUniqueId;
            internal int cExtension;
            internal IntPtr rgExtension;            // PCERT_EXTENSION
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_KEY_CONTEXT
        {
            internal int cbSize;
            internal IntPtr hNCryptKey;
            internal KeySpec dwKeySpec;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPT_KEY_PROV_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszContainerName;

            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszProvName;

            internal int dwProvType;

            internal int dwFlags;

            internal int cProvParam;

            internal IntPtr rgProvParam;        // PCRYPT_KEY_PROV_PARAM

            internal int dwKeySpec;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_OTHER_NAME
        {
            [MarshalAs(UnmanagedType.LPStr)]
            internal string pszObjId;

            internal CapiNative.CRYPTOAPI_BLOB Value;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_PUBLIC_KEY_INFO
        {
            private CapiNative.CRYPT_ALGORITHM_IDENTIFIER Algorithm;
            private CapiNative.CRYPT_BIT_BLOB PublicKey;
        }

        //
        // P/Invokes
        //

        [SuppressUnmanagedCodeSecurity]
        internal static class UnsafeNativeMethods
        {
            [DllImport("crypt32.dll", SetLastError = true)]
            internal static extern SafeCertContextHandle CertCreateSelfSignCertificate(SafeNCryptKeyHandle hCryptProvOrNCryptKey,
                                                                                       [In] ref CapiNative.CRYPTOAPI_BLOB pSubjectIssuerBlob,
                                                                                       X509CertificateCreationOptions dwFlags,
                                                                                       [In] ref CRYPT_KEY_PROV_INFO pKeyProvInfo,
                                                                                       [In] ref CapiNative.CRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,
                                                                                       [In] ref Win32Native.SYSTEMTIME pStartTime,
                                                                                       [In] ref Win32Native.SYSTEMTIME pEndTime,
                                                                                       [In] ref CERT_EXTENSIONS pExtensions);

            [DllImport("crypt32.dll")]
            internal static extern SafeCertContextHandle CertDuplicateCertificateContext(IntPtr certContext);       // CERT_CONTEXT *

            [DllImport("crypt32.dll")]
            internal static extern IntPtr CertFindExtension([MarshalAs(UnmanagedType.LPStr)] string pszObjId,
                                                            int cExtensions,
                                                            IntPtr rgExtensions);       // CERT_EXTENSION[cExtensions]

            [DllImport("crypt32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CertGetCertificateContextProperty(SafeCertContextHandle pCertContext,
                                                                          CertificateProperty dwPropId,
                                                                          [Out, MarshalAs(UnmanagedType.LPArray)] byte[] pvData,
                                                                          [In, Out] ref int pcbData);

            // Overload of CertSetCertificateContextProperty for setting CERT_KEY_CONTEXT_PROP_ID
            [DllImport("crypt32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CertSetCertificateContextProperty(SafeCertContextHandle pCertContext,
                                                                          CertificateProperty dwPropId,
                                                                          CertificatePropertySetFlags dwFlags,
                                                                          [In] ref CERT_KEY_CONTEXT pvData);

            [DllImport("crypt32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CryptAcquireCertificatePrivateKey(SafeCertContextHandle pCert,
                                                                          AcquireCertificateKeyOptions dwFlags,
                                                                          IntPtr pvReserved,        // void *
                                                                          [Out] out SafeNCryptKeyHandle phCryptProvOrNCryptKey,
                                                                          [Out] out int dwKeySpec,
                                                                          [Out, MarshalAs(UnmanagedType.Bool)] out bool pfCallerFreeProvOrNCryptKey);

            // This overload of CryptDecodeObjectEx must only be used with the CRYPT_DECODE_ALLOC flag
            [DllImport("crypt32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CryptDecodeObjectEx(CertificateEncodingType encodingType,
                                                            [MarshalAs(UnmanagedType.LPStr)] string lpszStructType,
                                                            IntPtr pbEncoded,       // BYTE[cbEncoded]
                                                            int cbEncoded,
                                                            DecodeObjectFlags flags,
                                                            IntPtr pDecodPara,      // PCRYPT_DECODE_PARA
                                                            [Out] out SafeLocalAllocHandle pvStructInfo,
                                                            [In, Out] ref int pcbStructInfo);
        }

        //
        // Wrapper methods
        //

        /// <summary>
        ///     Get the private key of a certificate
        /// </summary>
        [SecurityCritical]
        internal static SafeNCryptKeyHandle AcquireCngPrivateKey(SafeCertContextHandle certificateContext)
        {
            Debug.Assert(certificateContext != null, "certificateContext != null");
            Debug.Assert(!certificateContext.IsClosed && !certificateContext.IsInvalid, "!certificateContext.IsClosed && !certificateContext.IsInvalid");

            bool freeKey = true;
            SafeNCryptKeyHandle privateKey = null;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                if (!UnsafeNativeMethods.CryptAcquireCertificatePrivateKey(certificateContext,
                                                                           AcquireCertificateKeyOptions.AcquireOnlyNCryptKeys,
                                                                           IntPtr.Zero,
                                                                           out privateKey,
                                                                           out int keySpec,
                                                                           out freeKey))
                {
                    throw new CryptographicException(Marshal.GetLastWin32Error());
                }

                return privateKey;
            }
            finally
            {
                // If we're not supposed to release they key handle, then we need to bump the reference count
                // on the safe handle to correspond to the reference that Windows is holding on to.  This will
                // prevent the CLR from freeing the object handle.
                // 
                // This is certainly not the ideal way to solve this problem - it would be better for
                // SafeNCryptKeyHandle to maintain an internal bool field that we could toggle here and
                // have that suppress the release when the CLR calls the ReleaseHandle override.  However, that
                // field does not currently exist, so we'll use this hack instead.
                if (privateKey != null && !freeKey)
                {
                    bool addedRef = false;
                    privateKey.DangerousAddRef(ref addedRef);
                }
            }
        }

        /// <summary>
        ///     Create a self signed certificate around a CNG key
        /// </summary>
        [SecurityCritical]
        internal static SafeCertContextHandle CreateSelfSignedCertificate(CngKey key,
                                                                          bool takeOwnershipOfKey,
                                                                          byte[] subjectName,
                                                                          X509CertificateCreationOptions creationOptions,
                                                                          string signatureAlgorithmOid,
                                                                          DateTime startTime,
                                                                          DateTime endTime,
                                                                          X509ExtensionCollection extensions)
        {
            Debug.Assert(key != null, "key != null");
            Debug.Assert(subjectName != null, "subjectName != null");
            Debug.Assert(!String.IsNullOrEmpty(signatureAlgorithmOid), "!String.IsNullOrEmpty(signatureAlgorithmOid)");
            Debug.Assert(extensions != null, "extensions != null");

            // Create an algorithm identifier structure for the signature algorithm
            CapiNative.CRYPT_ALGORITHM_IDENTIFIER nativeSignatureAlgorithm = new CapiNative.CRYPT_ALGORITHM_IDENTIFIER
            {
                pszObjId = signatureAlgorithmOid,
                Parameters = new CapiNative.CRYPTOAPI_BLOB
                {
                    cbData = 0,
                    pbData = IntPtr.Zero
                }
            };

            // Convert the begin and expire dates to system time structures
            Win32Native.SYSTEMTIME nativeStartTime = new Win32Native.SYSTEMTIME(startTime);
            Win32Native.SYSTEMTIME nativeEndTime = new Win32Native.SYSTEMTIME(endTime);

            // Map the extensions into CERT_EXTENSIONS.  This involves several steps to get the
            // CERT_EXTENSIONS ready for interop with the native APIs.
            //   1. Build up the CERT_EXTENSIONS structure in managed code
            //   2. For each extension, create a managed CERT_EXTENSION structure; this requires allocating
            //      native memory for the blob pointer in the CERT_EXTENSION. These extensions are stored in
            //      the nativeExtensionArray variable.
            //   3. Get a block of native memory that can hold a native array of CERT_EXTENSION structures.
            //      This is the block referenced by the CERT_EXTENSIONS structure.
            //   4. For each of the extension structures created in step 2, marshal the extension into the
            //      native buffer allocated in step 3.
            CERT_EXTENSIONS nativeExtensions = new CERT_EXTENSIONS
            {
                cExtension = extensions.Count
            };
            CERT_EXTENSION[] nativeExtensionArray = new CERT_EXTENSION[extensions.Count];

            // Run this in a CER to ensure that we release any native memory allocated for the certificate
            // extensions.
            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                // Copy over each extension into a native extension structure, including allocating native
                // memory for its blob if necessary.
                for (int i = 0; i < extensions.Count; ++i)
                {
                    nativeExtensionArray[i] = new CERT_EXTENSION
                    {
                        pszObjId = extensions[i].Oid.Value,
                        fCritical = extensions[i].Critical,

                        Value = new CapiNative.CRYPTOAPI_BLOB
                        {
                            cbData = extensions[i].RawData.Length
                        }
                    };
                    if (nativeExtensionArray[i].Value.cbData > 0)
                    {
                        nativeExtensionArray[i].Value.pbData =
                            Marshal.AllocCoTaskMem(nativeExtensionArray[i].Value.cbData);
                        Marshal.Copy(extensions[i].RawData,
                                     0,
                                     nativeExtensionArray[i].Value.pbData,
                                     nativeExtensionArray[i].Value.cbData);
                    }
                }

                // Now that we've built up the extension array, create a block of native memory to marshal
                // them into.
                if (nativeExtensionArray.Length > 0)
                {
                    checked
                    {
                        // CERT_EXTENSION structures end with a pointer field, which means on all supported
                        // platforms they won't require any padding between elements of the array.
                        nativeExtensions.rgExtension =
                            Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(CERT_EXTENSION)) * nativeExtensionArray.Length);

                        for (int i = 0; i < nativeExtensionArray.Length; ++i)
                        {
                            ulong offset = (uint)i * (uint)Marshal.SizeOf(typeof(CERT_EXTENSION));
                            ulong next = offset + (ulong)nativeExtensions.rgExtension.ToInt64();
                            IntPtr nextExtensionAddr = new IntPtr((long)next);

                            Marshal.StructureToPtr(nativeExtensionArray[i], nextExtensionAddr, false);
                        }
                    }
                }

                // Setup a CRYPT_KEY_PROV_INFO for the key
                CRYPT_KEY_PROV_INFO keyProvInfo = new CRYPT_KEY_PROV_INFO
                {
                    pwszContainerName = key.UniqueName,
                    pwszProvName = key.Provider.Provider,
                    dwProvType = 0,     // NCRYPT
                    dwFlags = 0,
                    cProvParam = 0,
                    rgProvParam = IntPtr.Zero,
                    dwKeySpec = 0
                };

                //
                // Now that all of the needed data structures are setup, we can create the certificate
                //

                SafeCertContextHandle selfSignedCertHandle = null;
                unsafe
                {
                    fixed (byte* pSubjectName = &subjectName[0])
                    {
                        // Create a CRYPTOAPI_BLOB for the subject of the cert
                        CapiNative.CRYPTOAPI_BLOB nativeSubjectName = new CapiNative.CRYPTOAPI_BLOB
                        {
                            cbData = subjectName.Length,
                            pbData = new IntPtr(pSubjectName)
                        };

                        // Now that we've converted all the inputs to native data structures, we can generate
                        // the self signed certificate for the input key.
                        using (SafeNCryptKeyHandle keyHandle = key.Handle)
                        {
                            selfSignedCertHandle =
                                UnsafeNativeMethods.CertCreateSelfSignCertificate(keyHandle,
                                                                                  ref nativeSubjectName,
                                                                                  creationOptions,
                                                                                  ref keyProvInfo,
                                                                                  ref nativeSignatureAlgorithm,
                                                                                  ref nativeStartTime,
                                                                                  ref nativeEndTime,
                                                                                  ref nativeExtensions);
                            if (selfSignedCertHandle.IsInvalid)
                            {
                                throw new CryptographicException(Marshal.GetLastWin32Error());
                            }
                        }
                    }
                }

                Debug.Assert(selfSignedCertHandle != null, "selfSignedCertHandle != null");

                // Attach a key context to the certificate which will allow Windows to find the private key
                // associated with the certificate if the NCRYPT_KEY_HANDLE is ephemeral.
                // is done.
                using (SafeNCryptKeyHandle keyHandle = key.Handle)
                {
                    CERT_KEY_CONTEXT keyContext = new CERT_KEY_CONTEXT
                    {
                        cbSize = Marshal.SizeOf(typeof(CERT_KEY_CONTEXT)),
                        hNCryptKey = keyHandle.DangerousGetHandle(),
                        dwKeySpec = KeySpec.NCryptKey
                    };

                    bool attachedProperty = false;
                    int setContextError = 0;

                    // Run in a CER to ensure accurate tracking of the transfer of handle ownership
                    RuntimeHelpers.PrepareConstrainedRegions();
                    try { }
                    finally
                    {
                        CertificatePropertySetFlags flags = CertificatePropertySetFlags.None;
                        if (!takeOwnershipOfKey)
                        {
                            // If the certificate is not taking ownership of the key handle, then it should
                            // not release the handle when the context is released.
                            flags |= CertificatePropertySetFlags.NoCryptRelease;
                        }

                        attachedProperty =
                            UnsafeNativeMethods.CertSetCertificateContextProperty(selfSignedCertHandle,
                                                                                  CertificateProperty.KeyContext,
                                                                                  flags,
                                                                                  ref keyContext);
                        setContextError = Marshal.GetLastWin32Error();

                        // If we succesfully transferred ownership of the key to the certificate,
                        // then we need to ensure that we no longer release its handle.
                        if (attachedProperty && takeOwnershipOfKey)
                        {
                            keyHandle.SetHandleAsInvalid();
                        }
                    }

                    if (!attachedProperty)
                    {
                        throw new CryptographicException(setContextError);
                    }
                }

                return selfSignedCertHandle;
            }
            finally
            {
                //
                // In order to release all resources held by the CERT_EXTENSIONS we need to do three things
                //   1. Destroy each structure marshaled into the native CERT_EXTENSION array
                //   2. Release the memory used for the CERT_EXTENSION array
                //   3. Release the memory used in each individual CERT_EXTENSION
                //

                // Release each extension marshaled into the native buffer as well
                if (nativeExtensions.rgExtension != IntPtr.Zero)
                {
                    for (int i = 0; i < nativeExtensionArray.Length; ++i)
                    {
                        ulong offset = (uint)i * (uint)Marshal.SizeOf(typeof(CERT_EXTENSION));
                        ulong next = offset + (ulong)nativeExtensions.rgExtension.ToInt64();
                        IntPtr nextExtensionAddr = new IntPtr((long)next);

                        Marshal.DestroyStructure(nextExtensionAddr, typeof(CERT_EXTENSION));
                    }

                    Marshal.FreeCoTaskMem(nativeExtensions.rgExtension);
                }

                // If we allocated memory for any extensions, make sure to free it now
                for (int i = 0; i < nativeExtensionArray.Length; ++i)
                {
                    if (nativeExtensionArray[i].Value.pbData != IntPtr.Zero)
                    {
                        Marshal.FreeCoTaskMem(nativeExtensionArray[i].Value.pbData);
                    }
                }
            }
        }

        /// <summary>
        ///     Decode a certificate extension into a buffer.  This buffer must be closed before the
        ///     containing certificate is closed
        /// </summary>
        [SecurityCritical]
        internal static SafeLocalAllocHandle DecodeExtension(CERT_EXTENSION extension)
        {
            int decodedSize = 0;

            bool decoded = UnsafeNativeMethods.CryptDecodeObjectEx(CertificateEncodingType.Pkcs7AsnEncoding | CertificateEncodingType.X509AsnEncoding,
                                                                   extension.pszObjId,
                                                                   extension.Value.pbData,
                                                                   extension.Value.cbData,
                                                                   DecodeObjectFlags.AllocateMemory | DecodeObjectFlags.NoCopy | DecodeObjectFlags.ShareOidStrings,
                                                                   IntPtr.Zero,
                                                                   out SafeLocalAllocHandle decodedExtension,
                                                                   ref decodedSize);

            if (!decoded)
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }

            return decodedExtension;
        }

        /// <summary>
        ///     Duplicate the certificate context into a safe handle
        /// </summary>
        [SecurityCritical]
        internal static SafeCertContextHandle DuplicateCertContext(IntPtr context)
        {
            Debug.Assert(context != IntPtr.Zero);

            return UnsafeNativeMethods.CertDuplicateCertificateContext(context);
        }

        /// <summary>
        ///     Find the certificate extension identified with the given OID
        /// </summary>
        [SecurityCritical]
        [SecuritySafeCritical]
        internal static CERT_EXTENSION FindExtension(SafeCertContextHandle certificateContext, string extensionOid)
        {
            Debug.Assert(certificateContext != null, "certificateContext != null");
            Debug.Assert(!certificateContext.IsClosed && !certificateContext.IsInvalid, "!certificateContext.IsClosed && !certificateContext.IsInvalid");
            Debug.Assert(!String.IsNullOrEmpty(extensionOid), "!String.IsNullOrEmpty(extensionOid)");
            Debug.Assert(HasExtension(certificateContext, extensionOid), "HasExtension(extensionOid)");

            CERT_INFO certInfo = GetCertInfo(certificateContext);
            IntPtr extension = UnsafeNativeMethods.CertFindExtension(extensionOid,
                                                                     certInfo.cExtension,
                                                                     certInfo.rgExtension);
            return (CERT_EXTENSION)Marshal.PtrToStructure(extension, typeof(CERT_EXTENSION));
        }

        /// <summary>
        ///     Get an arbitrary property of a certificate
        /// </summary>
        [SecurityCritical]
        internal static byte[] GetCertificateProperty(SafeCertContextHandle certificateContext,
                                                      CertificateProperty property)
        {
            Debug.Assert(certificateContext != null, "certificateContext != null");
            Debug.Assert(!certificateContext.IsClosed && !certificateContext.IsInvalid, "!certificateContext.IsClosed && !certificateContext.IsInvalid");

            byte[] buffer = null;
            int bufferSize = 0;
            if (!UnsafeNativeMethods.CertGetCertificateContextProperty(certificateContext,
                                                                       property,
                                                                       buffer,
                                                                       ref bufferSize))
            {
                ErrorCode errorCode = (ErrorCode)Marshal.GetLastWin32Error();
                if (errorCode != ErrorCode.MoreData)
                {
                    throw new CryptographicException((int)errorCode);
                }
            }

            buffer = new byte[bufferSize];
            if (!UnsafeNativeMethods.CertGetCertificateContextProperty(certificateContext,
                                                                       property,
                                                                       buffer,
                                                                       ref bufferSize))
            {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }

            return buffer;
        }

        /// <summary>
        ///     Get the certificate context which corresponds to the given certificate info
        /// </summary>
        [SecurityCritical]
        internal static CERT_INFO GetCertInfo(SafeCertContextHandle certificateContext)
        {
            Debug.Assert(certificateContext != null, "certificateContext != null");
            Debug.Assert(!certificateContext.IsClosed && !certificateContext.IsInvalid, "!certificateContext.IsClosed && !certificateContext.IsInvalid");

            bool addedRef = false;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                certificateContext.DangerousAddRef(ref addedRef);

                CERT_CONTEXT context = (CERT_CONTEXT)Marshal.PtrToStructure(certificateContext.DangerousGetHandle(), typeof(CERT_CONTEXT));
                return (CERT_INFO)Marshal.PtrToStructure(context.pCertInfo, typeof(CERT_INFO));
            }
            finally
            {
                if (addedRef)
                {
                    certificateContext.DangerousRelease();
                }
            }
        }

        /// <summary>
        ///     Get a property of a certificate formatted as a structure
        /// </summary>
        [SecurityCritical]
        internal static T GetCertificateProperty<T>(SafeCertContextHandle certificateContext,
                                                    CertificateProperty property) where T : struct
        {
            Debug.Assert(certificateContext != null, "certificateContext != null");
            Debug.Assert(!certificateContext.IsClosed && !certificateContext.IsInvalid, "!certificateContext.IsClosed && !certificateContext.IsInvalid");

            byte[] rawProperty = GetCertificateProperty(certificateContext, property);
            Debug.Assert(rawProperty.Length >= Marshal.SizeOf(typeof(T)), "Property did not return expected structure");

            unsafe
            {
                fixed (byte* pRawProperty = &rawProperty[0])
                {
                    return (T)Marshal.PtrToStructure(new IntPtr(pRawProperty), typeof(T));
                }
            }
        }

        /// <summary>
        ///     Determine if a certificate context has a particular extension
        /// </summary>
        [SecurityCritical]
        [SecuritySafeCritical]
        internal static bool HasExtension(SafeCertContextHandle certificateContext, string extensionOid)
        {
            Debug.Assert(certificateContext != null, "certificateContext != null");
            Debug.Assert(!certificateContext.IsClosed && !certificateContext.IsInvalid, "!certificateContext.IsClosed && !certificateContext.IsInvalid");
            Debug.Assert(!String.IsNullOrEmpty(extensionOid), "!String.IsNullOrEmpty(extensionOid)");

            CERT_INFO certInfo = GetCertInfo(certificateContext);
            if (certInfo.cExtension == 0)
            {
                return false;
            }

            return UnsafeNativeMethods.CertFindExtension(extensionOid, certInfo.cExtension, certInfo.rgExtension) != IntPtr.Zero;
        }

        /// <summary>
        ///     Determine if a certificate has a specific property
        /// </summary>
        [SecurityCritical]
        internal static bool HasCertificateProperty(SafeCertContextHandle certificateContext,
                                                    CertificateProperty property)
        {
            Debug.Assert(certificateContext != null, "certificateContext != null");
            Debug.Assert(!certificateContext.IsClosed && !certificateContext.IsInvalid, "!certificateContext.IsClosed && !certificateContext.IsInvalid");

            byte[] buffer = null;
            int bufferSize = 0;
            bool gotProperty = UnsafeNativeMethods.CertGetCertificateContextProperty(certificateContext,
                                                                                     property,
                                                                                     buffer,
                                                                                     ref bufferSize);
            return gotProperty ||
                   (ErrorCode)Marshal.GetLastWin32Error() == ErrorCode.MoreData;
        }

        /// <summary>
        ///     Get the corresponding OID for an X509 certificate signature algorithm
        /// </summary>
        internal static string MapCertificateSignatureAlgorithm(X509CertificateSignatureAlgorithm signatureAlgorithm)
        {
            Debug.Assert(signatureAlgorithm >= X509CertificateSignatureAlgorithm.RsaSha1 &&
                         signatureAlgorithm <= X509CertificateSignatureAlgorithm.ECDsaSha512,
                         "Invalid signature algorithm");

            switch (signatureAlgorithm)
            {
                case X509CertificateSignatureAlgorithm.RsaSha1:
                    return CapiNative.WellKnownOids.RsaSha1;

                case X509CertificateSignatureAlgorithm.RsaSha256:
                    return CapiNative.WellKnownOids.RsaSha256;

                case X509CertificateSignatureAlgorithm.RsaSha384:
                    return CapiNative.WellKnownOids.RsaSha384;

                case X509CertificateSignatureAlgorithm.RsaSha512:
                    return CapiNative.WellKnownOids.RsaSha512;

                case X509CertificateSignatureAlgorithm.ECDsaSha1:
                    return CapiNative.WellKnownOids.ECDsaSha1;

                case X509CertificateSignatureAlgorithm.ECDsaSha256:
                    return CapiNative.WellKnownOids.ECDsaSha256;

                case X509CertificateSignatureAlgorithm.ECDsaSha384:
                    return CapiNative.WellKnownOids.ECDsaSha384;

                case X509CertificateSignatureAlgorithm.ECDsaSha512:
                    return CapiNative.WellKnownOids.ECDsaSha512;

                default:
                    Debug.Assert(false, "Unknown certificate signature algorithm");
                    return null;
            }
        }
    }
}
