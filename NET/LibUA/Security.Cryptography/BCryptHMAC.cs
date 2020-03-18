// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Globalization;
using System.Security;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     Generic implementation of HMAC which is implemented by the BCrypt layer of Cng. Concrete HMAC
    ///     classes should contain an instance of the BCryptHMAC type and delegate their work to that object.
    /// </summary>
    internal sealed class BCryptHMAC : HMAC, ICngAlgorithm
    {
        private SafeBCryptAlgorithmHandle m_algorithm;
        private SafeBCryptHashHandle m_hash;
        private CngProvider m_implementation;

        [SecurityCritical]
        [SecuritySafeCritical]
        internal BCryptHMAC(CngAlgorithm algorithm,
                            CngProvider algorithmProvider,
                            string hashName,
                            int blockSize,
                            byte[] key)
        {
            Debug.Assert(algorithm != null, "algorithm != null");
            Debug.Assert(algorithmProvider != null, "algorithmProvider != null");
            Debug.Assert(!String.IsNullOrEmpty(hashName), "!String.IsNullOrEmpty(hashName)");
            Debug.Assert(blockSize > 0, "blockSize > 0");
            Debug.Assert(key != null, "key != null");

            BlockSizeValue = blockSize;

            // We set the HashName up to be the CNG version of the hash, since the base type will instantiate
            // the algorithm, and the CNG versions have different FIPS characteristics than the standard implementations.
            HashName = String.Format(CultureInfo.InvariantCulture,
                                     "System.Security.Cryptography.{0}Cng, {1}",
                                     hashName,
                                     typeof(SHA256Cng).Assembly.FullName);

            m_implementation = algorithmProvider;

            m_algorithm = BCryptNative.OpenAlgorithm(algorithm.Algorithm,
                                                     algorithmProvider.Provider,
                                                     BCryptNative.AlgorithmProviderOptions.HmacAlgorithm);
            
            // Resetting the key will call Initialize for us, and get us setup with a hash handle,
            // so we don't need to create the hash handle ourselves
            Key = key;

            HashSizeValue = BCryptNative.GetInt32Property(m_hash, BCryptNative.HashPropertyName.HashLength) * 8;
        }

        public override bool CanReuseTransform
        {
            get { return true; }
        }

        public override bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        public override byte[] Key
        {
            set
            {
                // HMAC's Key setter will ensure that we're in a valid state to change the key
                base.Key = value;

                // Changing the key value requires us to create a new hash handle, so we need to reset
                Initialize();
            }
        }

        public CngProvider Provider
        {
            get { return m_implementation; }
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing)
                {
                    if (m_hash != null)
                    {
                        m_hash.Dispose();
                    }

                    if (m_algorithm != null)
                    {
                        m_algorithm.Dispose();
                    }
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        protected override void HashCore(byte[] rgb, int ib, int cb)
        {
            HashCoreImpl(rgb, ib, cb);
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        internal void HashCoreImpl(byte[] rgb, int ib, int cb)
        {
            if (rgb == null)
                throw new ArgumentNullException("rgb");
            if (ib < 0 || ib > rgb.Length - cb)
                throw new ArgumentOutOfRangeException("ib");
            if (cb < 0 || cb > rgb.Length)
                throw new ArgumentOutOfRangeException("cb");

            // Tell the base class that resetting the key is no longer allowed
            State = 1;

            byte[] data = new byte[cb];
            Buffer.BlockCopy(rgb, ib, data, 0, data.Length);
            BCryptNative.HashData(m_hash, data);
        }

        protected override byte[] HashFinal()
        {
            return HashFinalImpl();
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        internal byte[] HashFinalImpl()
        {
            return BCryptNative.FinishHash(m_hash);
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        public override void Initialize()
        {
            Debug.Assert(m_algorithm != null, "m_algorithm != null");

            base.Initialize();

            // If we have a previously used hash handle, we can clean it up now
            if (m_hash != null)
            {
                m_hash.Dispose();
            }

            m_hash = BCryptNative.CreateHash(m_algorithm, KeyValue);

            // We're allowed to reset the key at this point
            State = 0;
        }
    }
}
