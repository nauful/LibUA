// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;

namespace LibUA.Security.Cryptography.X509Certificates
{
    /// <summary>
    ///     X509 alternate name implementation for alternate names stored as strings.  THe
    ///     <see cref="AlternateNameType.DnsName" />, <see cref="AlternateNameType.EdiPartyName" />,
    ///     <see cref="AlternateNameType.RegisteredId" />, <see cref="AlternateNameType.Rfc822Name" />,
    ///     and <see cref="AlternateNameType.Url" /> alternate name types store their names as strings.
    /// </summary>
    public sealed class X509AlternateNameString : X509AlternateName
    {
        private string m_name;

        /// <summary>
        ///     Create an alternate name for the given string
        /// </summary>
        /// <exception cref="ArgumentNullException">if <paramref name="name"/> is null</exception>
        public X509AlternateNameString(AlternateNameType type, string name) : base(type)
        {
            if (name == null)
                throw new ArgumentNullException("name");

            m_name = name;
        }

        public override object AlternateName
        {
            get { return Name; }
        }

        /// <summary>
        ///     Alternate name
        /// </summary>
        public string Name
        {
            get { return m_name; }
        }

        public override bool Equals(object obj)
        {
            X509AlternateNameString other = obj as X509AlternateNameString;
            if (other == null)
            {
                return false;
            }

            return other.AlternateNameType == AlternateNameType &&
                   String.Equals(other.Name, Name, StringComparison.Ordinal);
        }

        public override int GetHashCode()
        {
            return AlternateNameType.GetHashCode() ^ AlternateName.GetHashCode();
        }
    }
}
