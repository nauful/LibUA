// Copyright (c) Microsoft Corporation.  All rights reserved.

using System.Net;
using System.Runtime.InteropServices;
using System.Security;

namespace LibUA.Security.Cryptography.X509Certificates
{
    /// <summary>
    ///     The X509Alternate name type represents alternate name information pulled from an X509
    ///     certificate's subject or issuer alternate names extension.  This type serves as the base for the
    ///     more specific alternate name types which can contain more detailed data about the name.
    /// </summary>
    public class X509AlternateName
    {
        private readonly AlternateNameType m_type;

        /// <summary>
        ///     Construct an empty X509AlternateName of the specified type
        /// </summary>
        public X509AlternateName(AlternateNameType type)
        {
            m_type = type;
        }

        /// <summary>
        ///     Get the type of alternate name this object represents
        /// </summary>
        public AlternateNameType AlternateNameType
        {
            get { return m_type; }
        }

        /// <summary>
        ///     Get the alternate name that this object represents.  The type of object returned from this
        ///     property depends upon how the specific alternate name type specifies its data.  Strongly
        ///     typed alternate name data can also be obtained from working with the subtypes directly.
        /// </summary>
        public virtual object AlternateName
        {
            get { return m_type; }
        }

        public override bool Equals(object obj)
        {
            X509AlternateName other = obj as X509AlternateName;
            if (other == null || other.GetType() != typeof(X509AlternateName))
            {
                return false;
            }

            return AlternateNameType == other.AlternateNameType;
        }

        public override int GetHashCode()
        {
            return AlternateNameType.GetHashCode();
        }

        public override string ToString()
        {
            return AlternateName.ToString();
        }

        /// <summary>
        ///     Create an X509Alternate name object from a native CERT_ALT_NAME_ENTRY structure
        /// </summary>
        [SecurityCritical]
        internal static X509AlternateName FromAltNameEntry(X509Native.CERT_ALT_NAME_ENTRY altNameEntry)
        {
            switch (altNameEntry.dwAltNameChoice)
            {
                case AlternateNameType.DirectoryName:
                    return new X509AlternateNameBlob(altNameEntry.dwAltNameChoice,
                                                     CapiNative.ReadBlob(altNameEntry.altName.DirectoryName));

                case AlternateNameType.DnsName:
                    return new X509AlternateNameString(altNameEntry.dwAltNameChoice,
                                                       Marshal.PtrToStringUni(altNameEntry.altName.pwszDNSName));

                case AlternateNameType.EdiPartyName:
                    return new X509AlternateNameString(altNameEntry.dwAltNameChoice,
                                                       Marshal.PtrToStringUni(altNameEntry.altName.pEdiPartyName));

                case AlternateNameType.IPAddress:
                    IPAddress ipAddress = new IPAddress(CapiNative.ReadBlob(altNameEntry.altName.IPAddress));
                    return new X509AlternateNameIPAddress(altNameEntry.dwAltNameChoice,
                                                          ipAddress);

                case AlternateNameType.OtherName:
                    X509Native.CERT_OTHER_NAME otherName =
                        (X509Native.CERT_OTHER_NAME)Marshal.PtrToStructure(altNameEntry.altName.pOtherName, typeof(X509Native.CERT_OTHER_NAME));

                    Oid2 otherNameOid = Oid2.FindByValue(otherName.pszObjId);
                    return new X509AlternateNameOther(CapiNative.ReadBlob(otherName.Value), otherNameOid);

                case AlternateNameType.RegisteredId:
                    return new X509AlternateNameString(altNameEntry.dwAltNameChoice,
                                                       Marshal.PtrToStringAnsi(altNameEntry.altName.pszRegisteredID));

                case AlternateNameType.Rfc822Name:
                    return new X509AlternateNameString(altNameEntry.dwAltNameChoice,
                                                       Marshal.PtrToStringUni(altNameEntry.altName.pwszRfc822Name));

                case AlternateNameType.Url:
                    return new X509AlternateNameString(altNameEntry.dwAltNameChoice,
                                                       Marshal.PtrToStringUni(altNameEntry.altName.pwszURL));

                case AlternateNameType.X400Address:
                    return new X509AlternateNameBlob(altNameEntry.dwAltNameChoice,
                                                     CapiNative.ReadBlob(altNameEntry.altName.x400Address));

                default:
                    return new X509AlternateName(altNameEntry.dwAltNameChoice);
            }
        }
    }
}
