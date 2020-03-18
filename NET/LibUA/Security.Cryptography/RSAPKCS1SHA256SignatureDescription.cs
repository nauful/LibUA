// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     <para>
    ///         The RSAPKCS1SHA256SignatureDescription class provides a signature description implementation
    ///         for RSA-SHA256 signatures. It allows XML digital signatures to be produced using the
    ///         http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 signature type.
    ///         RSAPKCS1SHA256SignatureDescription provides the same interface as other signature description
    ///         implementations shipped with the .NET Framework, such as
    ///         <see cref="RSAPKCS1SHA1SignatureDescription" />.
    ///     </para>
    ///     <para>
    ///         RSAPKCS1SHA256SignatureDescription is not generally intended for use on its own, instead it
    ///         should be consumed by higher level cryptography services such as the XML digital signature
    ///         stack. It can be registered in <see cref="CryptoConfig" /> so that these services can create
    ///         instances of this signature description and use RSA-SHA256 signatures.
    ///     </para>
    ///     <para>
    ///         Registration in CryptoConfig requires editing the machine.config file found in the .NET
    ///         Framework installation's configuration directory (such as
    ///         %WINDIR%\Microsoft.NET\Framework\v2.0.50727\Config or
    ///         %WINDIR%\Microsoft.NET\Framework64\v2.0.50727\Config) to include registration information on
    ///         the type. For example:
    ///     </para>
    ///     <example>
    ///         <![CDATA[
    ///             <configuration>
    ///               <mscorlib>
    ///                 <!-- ... -->
    ///                 <cryptographySettings>
    ///                   <cryptoNameMapping>
    ///                     <cryptoClasses>
    ///                       <cryptoClass RSASHA256SignatureDescription="Security.Cryptography.RSAPKCS1SHA256SignatureDescription, Security.Cryptography, Version=1.1.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
    ///                     </cryptoClasses>
    ///                     <nameEntry name="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" class="RSASHA256SignatureDescription" />
    ///                   </cryptoNameMapping>
    ///                 </cryptographySettings>
    ///               </mscorlib>
    ///             </configuration>
    ///         ]]>
    ///     </example>
    ///     <para>
    ///         After adding this registration entry, the assembly which contains the
    ///         RSAPKCS1SHA256SignatureDescription (in the example above Security.Cryptography.dll) needs to
    ///         be added to the GAC.
    ///    </para>
    ///    <para>
    ///         Note that on 64 bit machines, both the Framework and Framework64 machine.config files should
    ///         be updated, and if the signature description assembly is built bit-specific it needs to be
    ///         added to both the 32 and 64 bit GACs.
    ///     </para>
    ///     <para>
    ///         RSA-SHA256 signatures are first available on the .NET Framework 3.5 SP 1 and as such the
    ///         RSAPKCS1SHA256SignatureDescription requires .NET 3.5 SP 1 and Windows Server 2003 or greater
    ///         to work properly.
    ///     </para>
    ///     <para>
    ///         On Windows 2003, the default OID registrations are not setup for the SHA2 family of hash
    ///         algorithms, and this can cause the .NET Framework v3.5 SP 1 to be unable to create RSA-SHA2
    ///         signatures. To fix this problem, the <see cref="Oid2.RegisterSha2OidInformationForRsa" />
    ///         method can be called to create the necessary OID registrations.
    ///     </para>
    /// </summary>
    [SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "RSAPKCS", Justification = "This casing is to match the existing RSAPKCS1SHA1SignatureDescription type")]
    [SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "SHA", Justification = "This casing is to match the use of SHA throughout the framework")]
    public sealed class RSAPKCS1SHA256SignatureDescription : SignatureDescription
    {
        /// <summary>
        ///     Construct an RSAPKCS1SHA256SignatureDescription object. The default settings for this object
        ///     are:
        ///     <list type="bullet">
        ///         <item>Digest algorithm - <see cref="SHA256Managed" /></item>
        ///         <item>Key algorithm - <see cref="RSACryptoServiceProvider" /></item>
        ///         <item>Formatter algorithm - <see cref="RSAPKCS1SignatureFormatter" /></item>
        ///         <item>Deformatter algorithm - <see cref="RSAPKCS1SignatureDeformatter" /></item>
        ///     </list>
        /// </summary>
        public RSAPKCS1SHA256SignatureDescription()
        {
            KeyAlgorithm = typeof(RSACryptoServiceProvider).FullName;
            DigestAlgorithm = typeof(SHA256Managed).FullName;   // Note - SHA256CryptoServiceProvider is not registered with CryptoConfig
            FormatterAlgorithm = typeof (RSAPKCS1SignatureFormatter).FullName;
            DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).FullName;
        }

        public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            RSAPKCS1SignatureDeformatter deformatter = new RSAPKCS1SignatureDeformatter(key);
            deformatter.SetHashAlgorithm("SHA256");
            return deformatter;
        }

        public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(key);
            formatter.SetHashAlgorithm("SHA256");
            return formatter;
        }
    }
}
