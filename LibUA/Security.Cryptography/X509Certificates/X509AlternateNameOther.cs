// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Net;

namespace LibUA.Security.Cryptography.X509Certificates
{
    /// <summary>
    ///     X509 alternate name implementation for other forms of alternate names.  This type always uses
    ///     the <see cref="AlternateNameType.OtherName" /> alternate name type, and should have its type
    ///     determined via the value in its <see cref="Oid"/> property.
    /// </summary>
    public sealed class X509AlternateNameOther : X509AlternateNameBlob
    {
        private Oid2 m_oid;

        /// <summary>
        ///     Create an alternate name for the given blob
        /// </summary>
        /// <param name="blob">raw alternate name blob</param>
        /// <param name="oid">OID describing the type of alternate name</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="blob"/> or <paramref name="oid"/> are null
        /// </exception>
        public X509AlternateNameOther(byte[] blob, Oid2 oid)
            : base(AlternateNameType.OtherName, blob)
        {
            if (oid == null)
                throw new ArgumentNullException("oid");

            m_oid = oid;
        }

        /// <summary>
        ///     Get the OID representing the type of this alternate name
        /// </summary>
        public Oid2 Oid
        {
            get { return m_oid; }
        }

        public override bool Equals(object obj)
        {
            X509AlternateNameOther other = obj as X509AlternateNameOther;
            if (other == null)
            {
                return false;
            }

            return base.Equals(other) &&
                   String.Equals(other.Oid.Value, Oid.Value, StringComparison.Ordinal);
        }

        public override int GetHashCode()
        {
            return base.GetHashCode() ^ Oid.Value.GetHashCode();
        }

        public override string ToString()
        {
            return Oid.Value;
        }
    }
}
