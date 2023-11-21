// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using LibUA.Security.Cryptography.X509Certificates;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     <para>
    ///         The CngKeyExtensionMethods class provides several extension methods for the
    ///         <see cref="CngKey" />.  This type is in the Security.Cryptography namespace (not the
    ///         System.Security.Cryptography namespace), so in order to use these extension methods, you will
    ///         need to make sure you include this namespace as well as a reference to
    ///         Security.Cryptography.dll.
    ///     </para>
    ///     <para>
    ///         CngKey uses the NCrypt layer of CNG, and requires Windows Vista and the .NET Framework 3.5.
    ///     </para>
    /// </summary>
    public static class CngKeyExtensionMethods
    {
        /// <summary>
        ///     <para>
        ///         CreateSelfSignedCertificate creates a new self signed certificate issued to the specified
        ///         subject. The certificate will contain the key used to create the self signed certificate.
        ///         Since the certificate needs to be signed, the CngKey used must be usable for signing, which
        ///         means it must also contain a private key. If there is no private key, the operation will fail
        ///         with a CryptographicException indicating that "The key does not exist."
        ///     </para>
        ///     <para>
        ///         This overload creates a certificate which does take ownership of the underlying key - which
        ///         means that the input CngKey will be disposed before this method exits and should no longer
        ///         be used by the caller.
        ///     </para>
        /// </summary>
        /// <param name="key">key to wrap in a self signed certificate</param>
        /// <param name="subjectName">the name of hte subject the self-signed certificate will be issued to</param>
        /// <exception cref="ArgumentNullException">if <paramref name="subjectName" /> is null</exception>
        /// <exception cref="CryptographicException">if the certificate cannot be created</exception>
        public static X509Certificate2 CreateSelfSignedCertificate(this CngKey key,
                                                                   X500DistinguishedName subjectName)
        {
            X509CertificateCreationParameters creationParameters = new X509CertificateCreationParameters(subjectName)
            {
                TakeOwnershipOfKey = true
            };
            return CreateSelfSignedCertificate(key, creationParameters);
        }

        /// <summary>
        ///     <para>
        ///         CreateSelfSignedCertificate creates a new self signed certificate issued to the specified
        ///         subject. The certificate will contain the key used to create the self signed certificate.
        ///         Since the certificate needs to be signed, the CngKey used must be usable for signing, which
        ///         means it must also contain a private key. If there is no private key, the operation will fail
        ///         with a CryptographicException indicating that "The key does not exist."
        ///     </para>
        ///     <para>
        ///         If <paramref name="creationParameters"/> have TakeOwnershipOfKey set to true, the certificate
        ///         generated will own the key and the input CngKey will be disposed to ensure that the caller
        ///         doesn't accidentally use it beyond its lifetime (which is now controlled by the certificate
        ///         object).
        ///     </para>
        ///     <para>
        ///         Conversely, if TakeOwnershipOfKey is set to false, the API requires full trust to use, and
        ///         also requires that the caller ensure that the generated certificate does not outlive the
        ///         input CngKey object.
        ///     </para>
        /// </summary>
        /// <param name="key">key to wrap in a self signed certificate</param>
        /// <param name="creationParameters">parameters to customize the self-signed certificate</param>
        /// <exception cref="ArgumentNullException">if <paramref name="creationParameters" /> is null</exception>
        /// <exception cref="CryptographicException">if the certificate cannot be created</exception>
        /// <permission cref="PermissionSet">
        ///     This API requries full trust if <paramref name="creationParameters"/> specifies TakeOwnershipOfKey
        ///     to be false.
        /// </permission>
        [SecurityCritical]
        [SecuritySafeCritical]
        public static X509Certificate2 CreateSelfSignedCertificate(this CngKey key,
                                                                   X509Certificates.X509CertificateCreationParameters creationParameters)
        {
            if (creationParameters == null)
                throw new ArgumentNullException("creationParameters");

            // If we are not being asked to hand ownership of the key over to the certificate, then we need
            // ensure that we are running in a trusted context as we have no way to ensure that the caller
            // will not force the key to be cleaned up and then continue to use the dangling handle left in
            // the certificate.
            if (!creationParameters.TakeOwnershipOfKey)
            {
                new PermissionSet(PermissionState.Unrestricted).Demand();
            }

            using (SafeCertContextHandle selfSignedCertHandle =
                X509Native.CreateSelfSignedCertificate(key,
                                                       creationParameters.TakeOwnershipOfKey,
                                                       creationParameters.SubjectName.RawData,
                                                       creationParameters.CertificateCreationOptions,
                                                       X509Native.MapCertificateSignatureAlgorithm(creationParameters.SignatureAlgorithm),
                                                       creationParameters.StartTime,
                                                       creationParameters.EndTime,
                                                       creationParameters.ExtensionsNoDemand))
            {
                // We need to get the raw handle out of the safe handle because X509Certificate2 only
                // exposes an IntPtr constructor.  To do that we'll temporarially bump the ref count on
                // the handle.
                //
                // X509Certificate2 will duplicate the handle value in the .ctor, so once we've created
                // the certificate object, we can safely drop the ref count and dispose of our handle.
                X509Certificate2 certificate = null;
                bool addedRef = false;
                RuntimeHelpers.PrepareConstrainedRegions();
                try
                {
                    selfSignedCertHandle.DangerousAddRef(ref addedRef);
                    certificate = new X509Certificate2(selfSignedCertHandle.DangerousGetHandle());
                }
                finally
                {
                    if (addedRef)
                    {
                        selfSignedCertHandle.DangerousRelease();
                    }
                }

                // If we passed ownership of the key to the certificate, than destroy the key
                // now so that we don't continue to use it beyond the liftime of the cert.
                if (creationParameters.TakeOwnershipOfKey)
                {
                    key.Dispose();
                }

                return certificate;
            }
        }
    }
}
