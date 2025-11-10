// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;

namespace LibUA.Security.Cryptography.X509Certificates
{
    /// <summary>
    ///     X509 alternate name implementation for alternate names stored as blobs.  For instance,
    ///     <see cref="AlternateNameType.DirectoryName"/> and <see cref="AlternateNameType.X400Address" />
    ///     use alternate names stored as blobs.
    /// </summary>
    public class X509AlternateNameBlob : X509AlternateName
    {
        private readonly byte[] m_blob;

        /// <summary>
        ///     Create an alternate name for the given blob
        /// </summary>
        /// <exception cref="ArgumentNullException">if <paramref name="blob"/> is null</exception>
        public X509AlternateNameBlob(AlternateNameType type, byte[] blob)
            : base(type)
        {
            if (blob == null)
                throw new ArgumentNullException("blob");

            m_blob = new byte[blob.Length];
            Array.Copy(blob, m_blob, m_blob.Length);
        }

        public override object AlternateName
        {
            get { return GetBlob(); }
        }

        public override bool Equals(object obj)
        {
            X509AlternateNameBlob other = obj as X509AlternateNameBlob;
            if (other == null)
            {
                return false;
            }

            if (other.AlternateNameType != AlternateNameType)
            {
                return false;
            }

            if (other.m_blob.Length != m_blob.Length)
            {
                return false;
            }

            for (int i = 0; i < m_blob.Length; ++i)
            {
                if (other.m_blob[i] != m_blob[i])
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        ///     Get the name blob
        /// </summary>
        public byte[] GetBlob()
        {
            byte[] blob = new byte[m_blob.Length];
            Array.Copy(m_blob, blob, blob.Length);
            return blob;
        }

        public override int GetHashCode()
        {
            int hashCode = AlternateNameType.GetHashCode();

            if (m_blob.Length > 4)
            {
                for (int i = 0; i < m_blob.Length; i += 4)
                {
                    hashCode ^= BitConverter.ToInt32(m_blob, i);
                }
            }

            if (m_blob.Length > 0 && m_blob.Length % 4 != 0)
            {
                int remainder = 0;
                for (int i = 0; i < m_blob.Length % 4; ++i)
                {
                    remainder |= (m_blob[m_blob.Length - i - 1]) << (8 * i);
                }

                hashCode ^= remainder;
            }

            return hashCode;
        }

        public override string ToString()
        {
            return AlternateNameType.ToString();
        }
    }
}
