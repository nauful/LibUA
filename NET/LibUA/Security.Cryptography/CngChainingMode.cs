// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     The CngChainingMode class provides a pseudo-enumeration similar to <see cref="CngAlgorithm" />
    ///     which provides an enumeration over chaining modes that CNG supports. Several of the enumeration
    ///     values are the CNG equivalents of the <see cref="CipherMode"/> framework enumeration.
    /// </summary>
    [Serializable]
    public sealed class CngChainingMode : IEquatable<CngChainingMode>
    {
        private static CngChainingMode s_cbc;
        private static CngChainingMode s_ccm;
        private static CngChainingMode s_cfb;
        private static CngChainingMode s_ecb;
        private static CngChainingMode s_gcm;

        private string m_chainingMode;

        /// <summary>
        ///     Creates a new CngChainingMode for the chaining mode string. This constructor should generally
        ///     not be used, and instead the built in values for the standard chaining modes should be
        ///     preferred.
        /// </summary>
        /// <param name="chainingMode">chaining mode to create a CngChainingMode object for</param>
        /// <exception cref="ArgumentException">if <paramref name="chainingMode" /> is empty</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="chainingMode" /> is null</exception>
        public CngChainingMode(string chainingMode)
        {
            if (chainingMode == null)
                throw new ArgumentNullException("chainingMode");
            if (chainingMode.Length == 0)
                throw new ArgumentException("InvalidChainingModeName", "chainingMode");

            m_chainingMode = chainingMode;
        }

        /// <summary>
        ///     Get the string which represents this chaining mode to CNG
        /// </summary>
        public string ChainingMode
        {
            get { return m_chainingMode; }
        }

        public static bool operator ==(CngChainingMode left, CngChainingMode right)
        {
            if (Object.ReferenceEquals(left, null))
            {
                return Object.ReferenceEquals(right, null);
            }

            return left.Equals(right);
        }

        public static bool operator !=(CngChainingMode left, CngChainingMode right)
        {
            if (Object.ReferenceEquals(left, null))
            {
                return !Object.ReferenceEquals(right, null);
            }

            return !left.Equals(right);
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as CngChainingMode);
        }

        public bool Equals(CngChainingMode other)
        {
            if (Object.ReferenceEquals(other, null))
            {
                return false;
            }

            return m_chainingMode.Equals(other.ChainingMode);
        }

        public override int GetHashCode()
        {
            return m_chainingMode.GetHashCode();
        }

        public override string ToString()
        {
            return m_chainingMode;
        }

        //
        // Well known chaining modes
        //

        /// <summary>
        ///     Gets a CngChainingMode object for the cipher block chaining mode. This is equivalent to
        ///     CipherMode.Cbc in the managed enumeration.
        /// </summary>
        public static CngChainingMode Cbc
        {
            get
            {
                if (s_cbc == null)
                {
                    s_cbc = new CngChainingMode(BCryptNative.ChainingMode.Cbc);
                }

                return s_cbc;
            }
        }

        /// <summary>
        ///     Gets a CngChainingMode object for the counter with cipher block chaining MAC authenticated
        ///     chaining mode.
        /// </summary>
        public static CngChainingMode Ccm
        {
            get
            {
                if (s_ccm == null)
                {
                    s_ccm = new CngChainingMode(BCryptNative.ChainingMode.Ccm);
                }

                return s_ccm;
            }
        }

        /// <summary>
        ///     Gets a CngChainingMode object for the cipher feedback mode. This is equivalent to
        ///     CipherMode.Cfb in the managed enumeration.
        /// </summary>
        public static CngChainingMode Cfb
        {
            get
            {
                if (s_cfb == null)
                {
                    s_cfb = new CngChainingMode(BCryptNative.ChainingMode.Cfb);
                }

                return s_cfb;
            }
        }

        /// <summary>
        ///     Gets a CngChainingMode object for the electronic codebook mode. This is equivalent to
        ///     CipherMode.Ecb in the managed enumeration.
        /// </summary>
        public static CngChainingMode Ecb
        {
            get
            {
                if (s_ecb == null)
                {
                    s_ecb = new CngChainingMode(BCryptNative.ChainingMode.Ecb);
                }

                return s_ecb;
            }
        }

        /// <summary>
        ///     Gets a CngChainingMode object for the counter with Galois/counter mode authenticated chaining
        ///     mode.
        /// </summary>
        public static CngChainingMode Gcm
        {
            get
            {
                if (s_gcm == null)
                {
                    s_gcm = new CngChainingMode(BCryptNative.ChainingMode.Gcm);
                }

                return s_gcm;
            }
        }
    }
}
