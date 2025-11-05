// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;

namespace LibUA.Security.Cryptography.X509Certificates
{
    /// <summary>
    ///     The X509CertificateExtensionMethods type provides extension methods for the
    ///     <see cref="X509Certificate" /> class. X509CertificateExtensionMethods is in the
    ///     Security.Cryptography.X509Certificates namespace (not the
    ///     System.Security.Cryptography.X509Certificates namespace), so in order to use these extension
    ///     methods, you will need to make sure you include this namespace as well as a reference to
    ///     Security.Cryptography.dll. 
    /// </summary>
    public static class X509CertificateExtensionMethods
    {
        /// <summary>
        ///     Get all the alternate names encoded under a specific extension OID.  The <see
        ///     cref="GetIssuerAlternateNames" /> and <see cref="GetSubjectAlternateNames" /> extension
        ///     methods provide direct access to the subject and issuer names, which can be friendlier to
        ///     use than this method.
        /// </summary>
        /// <param name="certificate">X509 certificate to get the alternate names of</param>
        /// <param name="alternateNameExtensionOid">OID representing the alternate names to retrieve</param>
        /// <exception cref="ArgumentNullException">if <paramref name="alternateNameExtensionOid"/> is null</exception>
        /// <permission cref="PermissionSet">
        ///     The immediate caller must be fully trusted to use this method.
        /// </permission>
        [SecurityCritical]
        [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        public static IList<X509AlternateName> GetAlternateNames(this X509Certificate certificate,
                                                                 Oid2 alternateNameExtensionOid)
        {
            if (alternateNameExtensionOid == null)
                throw new ArgumentNullException("alternateNameExtensionOid");

            List<X509AlternateName> alternateNames = new List<X509AlternateName>();

            using (SafeCertContextHandle certContext = certificate.GetCertificateContext())
            {
                // Make sure we have the extension requested
                if (X509Native.HasExtension(certContext, alternateNameExtensionOid.Value))
                {
                    // If so, get it from the certificate, and decode it into a buffer
                    X509Native.CERT_EXTENSION alternateNameExtension =
                        X509Native.FindExtension(certContext, alternateNameExtensionOid.Value);

                    using (SafeLocalAllocHandle decodedBuffer = X509Native.DecodeExtension(alternateNameExtension))
                    {
                        // This buffer contains CERT_ALT_NAME_INFO which points us at the alternate names we
                        // were looking for
                        X509Native.CERT_ALT_NAME_INFO altNameInfo = decodedBuffer.Read<X509Native.CERT_ALT_NAME_INFO>(0);
                        for (int i = 0; i < altNameInfo.cAltEntry; ++i)
                        {
                            unsafe
                            {
                                X509Native.CERT_ALT_NAME_ENTRY* pAltNameEntry = (X509Native.CERT_ALT_NAME_ENTRY*)altNameInfo.rgAltEntry;
                                alternateNames.Add(X509AlternateName.FromAltNameEntry(pAltNameEntry[i]));
                            }
                        }
                    }
                }

            }

            return alternateNames;
        }

        /// <summary>
        ///     Get a <see cref="SafeCertContextHandle" /> for the X509 certificate.  The caller of this
        ///     method owns the returned safe handle, and should dispose of it when they no longer need it. 
        ///     This handle can be used independently of the lifetime of the original X509 certificate.
        /// </summary>
        /// <permission cref="SecurityPermission">
        ///     The immediate caller must have SecurityPermission/UnmanagedCode to use this method
        /// </permission>
        [SecurityCritical]
        [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
        public static SafeCertContextHandle GetCertificateContext(this X509Certificate certificate)
        {
            SafeCertContextHandle certContext = X509Native.DuplicateCertContext(certificate.Handle);

            // Make sure to keep the X509Certificate object alive until after its certificate context is
            // duplicated, otherwise it could end up being closed out from underneath us before we get a
            // chance to duplicate the handle.
            GC.KeepAlive(certificate);

            return certContext;
        }

        /// <summary>
        ///     Get all of the alternate names a certificate has for its issuer
        /// </summary>
        [SecurityCritical]
        [SecuritySafeCritical]
        public static IEnumerable<X509AlternateName> GetIssuerAlternateNames(this X509Certificate certificate)
        {
            List<X509AlternateName> alternateNames = new List<X509AlternateName>();

            Oid2 extensionOid = Oid2.FindByValue(CapiNative.WellKnownOids.IssuerAlternateName,
                                                 OidGroup.ExtensionOrAttribute);
            alternateNames.AddRange(certificate.GetAlternateNames(extensionOid));

            Oid2 extensionOid2 = Oid2.FindByValue(CapiNative.WellKnownOids.IssuerAlternateName2,
                                                  OidGroup.ExtensionOrAttribute);
            alternateNames.AddRange(certificate.GetAlternateNames(extensionOid2));

            return alternateNames;
        }

        /// <summary>
        ///     Get all of the alternate names a certificate has for its subject
        /// </summary>
        [SecurityCritical]
        [SecuritySafeCritical]
        public static IEnumerable<X509AlternateName> GetSubjectAlternateNames(this X509Certificate certificate)
        {
            List<X509AlternateName> alternateNames = new List<X509AlternateName>();

            Oid2 extensionOid = Oid2.FindByValue(CapiNative.WellKnownOids.SubjectAlternateName,
                                                 OidGroup.ExtensionOrAttribute);
            alternateNames.AddRange(certificate.GetAlternateNames(extensionOid));

            Oid2 extensionOid2 = Oid2.FindByValue(CapiNative.WellKnownOids.SubjectAlternateName2,
                                                  OidGroup.ExtensionOrAttribute);
            alternateNames.AddRange(certificate.GetAlternateNames(extensionOid2));

            return alternateNames;
        }

        /// <summary>
        ///     The HasCngKey method returns true if the X509Certificate is referencing a key stored with with
        ///     NCrypt in CNG. It will return true if the certificate's key is a reference to a key stored in
        ///     CNG, and false otherwise. For instance, if the key is stored with CAPI or if the key is not
        ///     linked by the certificate and is contained directly in it, this method will return false.
        /// </summary>
        [SecurityCritical]
        [SecuritySafeCritical]
        public static bool HasCngKey(this X509Certificate certificate)
        {
            using (SafeCertContextHandle certContext = certificate.GetCertificateContext())
            {
                if (X509Native.HasCertificateProperty(certContext,
                                                      X509Native.CertificateProperty.KeyProviderInfo))
                {
                    X509Native.CRYPT_KEY_PROV_INFO keyProvInfo =
                        X509Native.GetCertificateProperty<X509Native.CRYPT_KEY_PROV_INFO>(certContext, X509Native.CertificateProperty.KeyProviderInfo);

                    return keyProvInfo.dwProvType == 0;
                }
                else
                {
                    return false;
                }
            }
        }
    }
}
