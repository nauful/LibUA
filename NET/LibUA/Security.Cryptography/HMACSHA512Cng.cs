// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     <para>
    ///         The HMACSHA512Cng class provides a wrapper for the CNG implementation of the HMAC SHA512
    ///         algorithm. It provides the same interface as the other HMAC implementations shipped with the
    ///         .NET Framework, including <see cref="HMACSHA256" />
    ///     </para>
    ///     <para>
    ///         HMACSHA512Cng uses the BCrypt layer of CNG to do its work, and requires Windows Vista and the
    ///         .NET Framework 3.5.
    ///     </para>
    ///     <para>
    ///         Since most of the HMACSHA512Cng APIs are inherited from the <see cref="HMAC" /> base class,
    ///         please see the MSDN documentation for HMAC for a complete description.
    ///     </para>
    /// </summary>
    public sealed class HMACSHA512Cng : HMAC, ICngAlgorithm
    {
        private const int BlockSize = 128;

        private readonly BCryptHMAC m_hmac;

        /// <summary>
        ///     Constructs a HMACSHA512Cng object with a randomly generated key, which will use the Microsoft
        ///     PrimitiveAlgorithm Provider to do its work.
        /// </summary>
        public HMACSHA512Cng() : this(RNGCng.GenerateKey(BlockSize))
        {
        }

        /// <summary>
        ///     Constructs a HMACSHA512Cng object using the given key, which will use the Microsoft
        ///     Primitive Algorithm Provider to do its work.
        /// </summary>
        /// <param name="key">key to use when calculating the HMAC</param>
        /// <exception cref="ArgumentNullException">if <paramref name="key"/> is null</exception>
        public HMACSHA512Cng(byte[] key) : this(key, CngProvider2.MicrosoftPrimitiveAlgorithmProvider)
        {
        }

        /// <summary>
        ///     Constructs a HMACSHA512Cng object using the given key, which will calculate the HMAC using the
        ///     given algorithm provider and key.
        /// </summary>
        /// <param name="key">key to use when calculating the HMAC</param>
        /// <param name="algorithmProvider">algorithm provider to calculate the HMAC in</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="key"/> or <paramref name="algorithmProvider"/> are null
        /// </exception>
        public HMACSHA512Cng(byte[] key, CngProvider algorithmProvider)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            if (algorithmProvider == null)
                throw new ArgumentNullException("algorithmProvider");

            m_hmac = new BCryptHMAC(CngAlgorithm.Sha512, algorithmProvider, "SHA512", BlockSize, key);
            HashName = m_hmac.HashName;
        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing)
                {
                    if (m_hmac != null)
                    {
                        (m_hmac as IDisposable).Dispose();
                    }
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }

        //
        // Forwarded APIs
        //

        public override bool CanReuseTransform
        {
            get { return m_hmac.CanReuseTransform; }
        }

        public override bool CanTransformMultipleBlocks
        {
            get { return m_hmac.CanTransformMultipleBlocks; }
        }

        public override byte[] Hash
        {
            get { return m_hmac.Hash; }
        }

        public override int HashSize
        {
            get { return m_hmac.HashSize; }
        }

        public override int InputBlockSize
        {
            get { return m_hmac.InputBlockSize; }
        }

        public override byte[] Key
        {
            get { return m_hmac.Key; }
            set { m_hmac.Key = value; }
        }

        public override int OutputBlockSize
        {
            get { return m_hmac.OutputBlockSize; }
        }

        public CngProvider Provider
        {
            get { return m_hmac.Provider; }
        }

        protected override void HashCore(byte[] rgb, int ib, int cb)
        {
            m_hmac.HashCoreImpl(rgb, ib, cb);
        }

        protected override byte[] HashFinal()
        {
            return m_hmac.HashFinalImpl();
        }

        public override void Initialize()
        {
            m_hmac.Initialize();
        }
    }
}
