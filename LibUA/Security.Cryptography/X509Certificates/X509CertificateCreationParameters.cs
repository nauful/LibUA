// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;

namespace LibUA.Security.Cryptography.X509Certificates
{
    /// <summary>
    ///     The X509CertificateCreationParameters class allows customization of the properties of an X509
    ///     certificate that is being created. For instance, these parameters can be used with the
    ///     <see cref="CngKeyExtensionMethods.CreateSelfSignedCertificate(CngKey, X509CertificateCreationParameters)" />
    ///     API.
    /// </summary>
    public sealed class X509CertificateCreationParameters
    {
        private X500DistinguishedName m_subjectName;
        private X509CertificateCreationOptions m_certificateCreationOptions = X509CertificateCreationOptions.None;
        private X509CertificateSignatureAlgorithm m_signatureAlgorithm = X509CertificateSignatureAlgorithm.RsaSha1;
        private DateTime m_endTime = DateTime.UtcNow.AddYears(1);
        private DateTime m_startTime = DateTime.UtcNow;
        private X509ExtensionCollection m_extensions = new X509ExtensionCollection();
        private bool m_takeOwnershipOfKey = true;

        /// <summary>
        ///     Creates a new X509CertificateCreationParameters object which can be used to create a new X509
        ///     certificate issued to the specified subject.
        /// </summary>
        /// <param name="subjectName">The name of the subject the new certificate will be issued to</param>
        /// <exception cref="ArgumentNullException">if <paramref name="subjectName" /> is null</exception>
        public X509CertificateCreationParameters(X500DistinguishedName subjectName)
        {
            if (subjectName == null)
                throw new ArgumentNullException("subjectName");

            m_subjectName = new X500DistinguishedName(subjectName);
        }

        /// <summary>
        ///     Gets or sets the flags used to create the X509 certificate. The default value is
        ///     X509CertificateCreationOptions.DoNotLinkKeyInformation.
        /// </summary>
        public X509CertificateCreationOptions CertificateCreationOptions
        {
            get { return m_certificateCreationOptions; }
            set { m_certificateCreationOptions = value; }
        }

        /// <summary>
        ///     Gets or sets the expiration date of the newly created certificate. If not set, this property
        ///     defaults to one year after the X509CertificateCreationParameters object is constructed.
        /// </summary>
        public DateTime EndTime
        {
            get { return m_endTime; }
            set { m_endTime = value; }
        }

        /// <summary>
        ///     The Extensions property holds a collection of the X509Extensions that will be applied to the
        ///     newly created certificate.
        /// </summary>
        /// <permission cref="SecurityPermission">
        ///     This property requires SecurityPermission/UnmanagedCode to access
        /// </permission>
        public X509ExtensionCollection Extensions
        {
            [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
            [SecurityCritical]
            [SecuritySafeCritical]
            get
            {
                return ExtensionsNoDemand;
            }
        }

        internal X509ExtensionCollection ExtensionsNoDemand
        {
            [SecurityCritical]
            get
            {
                return m_extensions;
            }
        }

        /// <summary>
        ///     Gets or sets the algorithm which will be used to sign the newly created certificate. If this
        ///     property is not set, the default value is X509CertificateSignatureAlgorithm.RsaSha1.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     if the value specified is not a member of the <see cref="X509CertificateSignatureAlgorithm" />
        ///     enumeration.
        /// </exception>
        public X509CertificateSignatureAlgorithm SignatureAlgorithm
        {
            get { return m_signatureAlgorithm; }

            set
            {
                if (value < X509CertificateSignatureAlgorithm.RsaSha1 ||
                    value > X509CertificateSignatureAlgorithm.ECDsaSha512)
                {
                    throw new ArgumentOutOfRangeException("value");
                }

                m_signatureAlgorithm = value;
            }
        }

        /// <summary>
        ///     Gets or sets a value indicating which object owns the lifetime of the incoming key
        ///     once the certificate is created.  If set to true, then the certificate owns the lifetime
        ///     of the key and the key object may be destroyed.  If set to false, the key object continues
        ///     to own the key lifetime and must therefore outlive the certificate.
        /// </summary>
        public bool TakeOwnershipOfKey
        {
            get { return m_takeOwnershipOfKey; }
            set { m_takeOwnershipOfKey = value; }
        }

        /// <summary>
        ///     Gets or sets the name of the subject that the newly created certificate will be issued to.
        /// </summary>
        /// <exception cref="ArgumentNullException">if SubjectName is set to a null value</exception>
        public X500DistinguishedName SubjectName
        {
            get { return new X500DistinguishedName(m_subjectName); }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                m_subjectName = new X500DistinguishedName(value);
            }
        }

        /// <summary>
        ///     Gets or sets the time that the newly created certificate will become valid. If not set, this
        ///     property defaults to the time that the X509CertificateCreationParameters object is created.
        /// </summary>
        public DateTime StartTime
        {
            get { return m_startTime; }
            set { m_startTime = value; }
        }
    }
}
