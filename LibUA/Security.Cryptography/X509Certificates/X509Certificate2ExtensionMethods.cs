// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security;
using System.Security.Permissions;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using LibUA.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace LibUA.Security.Cryptography.X509Certificates
{
    /// <summary>
    ///     The X509Certificate2ExtensionMethods type provides several extension methods for the
    ///     <see cref="X509Certificate2" /> class. This type is in the Security.Cryptography.X509Certificates
    ///     namespace (not the System.Security.Cryptography.X509Certificates namespace), so in order to use
    ///     these extension methods, you will need to make sure you include this namespace as well as a
    ///     reference to Security.Cryptography.dll.
    /// </summary>
    public static class X509Certificate2ExtensionMethods
    {
        /// <summary>
        ///     <para>
        ///         The GetCngPrivateKey method will return a <see cref="CngKey"/> representing the private
        ///         key of an X.509 certificate which has its private key stored with NCrypt rather than with
        ///         CAPI. If the key is not stored with NCrypt or if there is no private key available,
        ///         GetCngPrivateKey returns null.
        ///     </para>
        ///     <para>
        ///         The HasCngKey method can be used to test if the certificate does have its private key
        ///         stored with NCrypt.
        ///     </para>
        ///     <para>
        ///         The X509Certificate that is used to get the key must be kept alive for the lifetime of the
        ///         CngKey that is returned - otherwise the handle may be cleaned up when the certificate is
        ///         finalized.
        ///     </para>
        /// </summary>
        /// <permission cref="SecurityPermission">The caller of this method must have SecurityPermission/UnmanagedCode.</permission>
        [SecurityCritical]
        [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
        [SuppressMessage("Microsoft.Security", "CA2122:DoNotIndirectlyExposeMethodsWithLinkDemands", Justification = "Safe use of LinkDemand methods")]
        public static CngKey GetCngPrivateKey(this X509Certificate2 certificate)
        {
            if (!certificate.HasPrivateKey || !certificate.HasCngKey())
            {
                return null;
            }
            
            using (SafeCertContextHandle certContext = certificate.GetCertificateContext())
            using (SafeNCryptKeyHandle privateKeyHandle = X509Native.AcquireCngPrivateKey(certContext))
            {
                // We need to assert for full trust when opening the CNG key because
                // CngKey.Open(SafeNCryptKeyHandle) does a full demand for full trust, and we want to allow
                // access to a certificate's private key by anyone who has access to the certificate itself.
                new PermissionSet(PermissionState.Unrestricted).Assert();
                return CngKey.Open(privateKeyHandle, CngKeyHandleOpenOptions.None);
            }
        }
    }
}
