// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Net;

namespace LibUA.Security.Cryptography.X509Certificates
{
    /// <summary>
    ///     X509 alternate name implementation for alternate names stored as IP addresses.  The
    ///     <see cref="AlternateNameType.IPAddress"/> alternate name type is stored as an IP address.
    /// </summary>
    public sealed class X509AlternateNameIPAddress : X509AlternateName
    {
        private IPAddress m_address;

        /// <summary>
        ///     Create an alternate name for the given IP address
        /// </summary>
        /// <exception cref="ArgumentNullException">if <paramref name="address"/> is null</exception>
        public X509AlternateNameIPAddress(AlternateNameType type, IPAddress address) : base(type)
        {
            if (address == null)
                throw new ArgumentNullException("address");

            m_address = address;
        }

        /// <summary>
        ///     IP address held in the name
        /// </summary>
        public IPAddress Address
        {
            get { return m_address; }
        }

        public override object AlternateName
        {
            get { return Address; }
        }

        public override bool Equals(object obj)
        {
            X509AlternateNameIPAddress other = obj as X509AlternateNameIPAddress;
            if (other == null)
            {
                return false;
            }

            return other.AlternateNameType == AlternateNameType &&
                   other.Address.Equals(Address);
        }

        public override int GetHashCode()
        {
            return AlternateNameType.GetHashCode() ^ Address.GetHashCode();
        }
    }
}
