// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Security;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     Generic crypto transform, which implements authenticated symmetric encryption and decryption for
    ///     algorithms implemented in the BCrypt layer of CNG.  This type is used as the workhorse for the
    ///     BCryptAuthenticatedSymmetricAlgorithm generic BCrypt authenticated symmetric algorithm
    ///     implementation.
    /// </summary>
    internal sealed class BCryptAuthenticatedSymmetricCryptoTransform : CriticalFinalizerObject,
                                                                        IAuthenticatedCryptoTransform,
                                                                        IDisposable
    {
        private SafeBCryptAlgorithmHandle m_algorithm;
        private BCryptNative.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO m_authInfo;
        private byte[] m_chainData;
        private bool m_chainingSupported;
        private SafeBCryptKeyHandle m_key;

        private MemoryStream m_inputBuffer;
        private bool m_encrypting;
        private bool m_transformedFinalBlock;

        /// <summary>
        ///     Create an encrypting authenticated symmetric algorithm transform.  This type takes ownership
        ///     of the incoming algorithm handle, which should no longer be used by the calling code after
        ///     it has called this constructor.
        /// </summary>
        [SecurityCritical]
        internal BCryptAuthenticatedSymmetricCryptoTransform(SafeBCryptAlgorithmHandle algorithm,
                                                             byte[] key,
                                                             byte[] nonce,
                                                             byte[] authenticatedData,
                                                             bool chainingSupported,
                                                             int tagSize) :
            this(algorithm, key, nonce, authenticatedData, new byte[tagSize / 8], chainingSupported)
        {
            m_encrypting = true;
        }

        /// <summary>
        ///     Create a decrypting authenticated symmetric algorithm transform.  This type takes ownership
        ///     of the incoming algorithm handle, which should no longer be used by the calling code after
        ///     it has called this constructor.
        /// </summary>
        [SecurityCritical]
        internal BCryptAuthenticatedSymmetricCryptoTransform(SafeBCryptAlgorithmHandle algorithm,
                                                             byte[] key,
                                                             byte[] nonce,
                                                             byte[] authenticatedData,
                                                             byte[] tag,
                                                             bool chainingSupported)
        {
            Debug.Assert(algorithm != null, "algorithm != null");
            Debug.Assert(!algorithm.IsClosed && !algorithm.IsInvalid, "!algorithm.IsClosed && !algorithm.IsInvalid");

            if (key == null)
                throw new ArgumentNullException("key");
            if (tag == null)
                throw new ArgumentNullException("tag");

            bool initializationComplete = false;

            RuntimeHelpers.PrepareConstrainedRegions();
            try
            {
                m_algorithm = algorithm;
                m_key = BCryptNative.ImportSymmetricKey(algorithm, key);

                // Initialize the padding info structure.
                m_authInfo = new BCryptNative.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                BCryptNative.InitializeAuthnenticatedCipherModeInfo(ref m_authInfo);

                if (nonce != null)
                {
                    m_authInfo.cbNonce = nonce.Length;
                    m_authInfo.pbNonce = Marshal.AllocCoTaskMem(m_authInfo.cbNonce);
                    Marshal.Copy(nonce, 0, m_authInfo.pbNonce, m_authInfo.cbNonce);
                }

                if (authenticatedData != null)
                {
                    m_authInfo.cbAuthData = authenticatedData.Length;
                    m_authInfo.pbAuthData = Marshal.AllocCoTaskMem(m_authInfo.cbAuthData);
                    Marshal.Copy(authenticatedData, 0, m_authInfo.pbAuthData, m_authInfo.cbAuthData);
                }

                if (chainingSupported)
                {
                    m_chainingSupported = chainingSupported;

                    m_authInfo.cbMacContext = tag.Length;
                    m_authInfo.pbMacContext = Marshal.AllocCoTaskMem(m_authInfo.cbMacContext);

                    BCryptNative.BCRYPT_KEY_LENGTHS_STRUCT tagLengths =
                        BCryptNative.GetValueTypeProperty<SafeBCryptAlgorithmHandle, BCryptNative.BCRYPT_KEY_LENGTHS_STRUCT>(
                            algorithm,
                            BCryptNative.ObjectPropertyName.AuthTagLength);

                    m_chainData = new byte[tagLengths.dwMaxLength];
                }
                else
                {
                    m_inputBuffer = new MemoryStream();
                }

                m_authInfo.cbTag = tag.Length;
                m_authInfo.pbTag = Marshal.AllocCoTaskMem(m_authInfo.cbTag);
                Marshal.Copy(tag, 0, m_authInfo.pbTag, m_authInfo.cbTag);

                // Set chaining mode if supported.
                if (CanChainBlocks)
                {
                    m_authInfo.dwFlags |= BCryptNative.AuthenticatedCipherModeInfoFlags.ChainCalls;
                }

                initializationComplete = true;
            }
            finally
            {
                // If we failed to complete initialization we may have already allocated some native
                // resources.  Clean those up before leaving the constructor.
                if (!initializationComplete)
                {
                    Dispose();
                }
            }
        }

        ~BCryptAuthenticatedSymmetricCryptoTransform()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        [ReliabilityContract(Consistency.MayCorruptInstance, Cer.Success)]
        private void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (m_key != null)
                {
                    m_key.Dispose();
                }

                if (m_algorithm != null)
                {
                    m_algorithm.Dispose();
                }

                if (m_inputBuffer != null)
                {
                    m_inputBuffer.Dispose();
                }
            }

            if (m_authInfo.pbAuthData != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(m_authInfo.pbAuthData);
                m_authInfo.pbAuthData = IntPtr.Zero;
                m_authInfo.cbAuthData = 0;
            }

            if (m_authInfo.pbMacContext != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(m_authInfo.pbMacContext);
                m_authInfo.pbMacContext = IntPtr.Zero;
                m_authInfo.cbMacContext = 0;
            }

            if (m_authInfo.pbNonce != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(m_authInfo.pbNonce);
                m_authInfo.pbNonce = IntPtr.Zero;
                m_authInfo.cbNonce = 0;
            }

            if (m_authInfo.pbTag != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(m_authInfo.pbTag);
                m_authInfo.pbTag = IntPtr.Zero;
                m_authInfo.cbTag = 0;
            }
        }

        /// <summary>
        ///     Can the transform chain multiple blocks of ciphertext, or must they all come at once.
        /// </summary>
        public bool CanChainBlocks
        {
            get { return m_chainingSupported; }
        }

        /// <summary>
        ///     Gets a value indicating whether the transform can be reused.
        /// </summary>
        public bool CanReuseTransform
        {
            get { return false; }
        }

        /// <summary>
        ///     Gets a value indicating whether the transform can process multiple blocks at once.
        /// </summary>
        public bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        /// <summary>
        ///     Gets the input block length in bytes.
        /// </summary>
        public int InputBlockSize
        {
            [SecurityCritical]
            [SecuritySafeCritical]
            get { return BCryptNative.GetInt32Property(m_algorithm, BCryptNative.ObjectPropertyName.BlockLength); }
        }

        /// <summary>
        ///     Gets the output block length in bytes.
        /// </summary>
        public int OutputBlockSize
        {
            [SecurityCritical]
            [SecuritySafeCritical]
            get { return BCryptNative.GetInt32Property(m_algorithm, BCryptNative.ObjectPropertyName.BlockLength); }
        }

        /// <summary>
        ///     Get the authentication tag generated from encryption.
        /// </summary>
        [SecurityCritical]
        [SecuritySafeCritical]
        public byte[] GetTag()
        {
            // Authentication tags are only generated for encryption operations - they are input to decryption
            // operations.  They are also only generated after all of the data has been transformed.
            if (!m_encrypting)
                throw new InvalidOperationException("TagIsOnlyGeneratedDuringEncryption");
            if (!m_transformedFinalBlock)
                throw new InvalidOperationException("TagIsOnlyGeneratedAfterFinalBlock");

            byte[] tag = new byte[m_authInfo.cbTag];
            Marshal.Copy(m_authInfo.pbTag, tag, 0, m_authInfo.cbTag);
            return tag;
        }
        

        /// <summary>
        ///     Transforms some blocks of input data, but don't finalize the transform
        /// </summary>
        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (m_transformedFinalBlock)
                throw new InvalidOperationException("AlreadyTransformedFinalBlock");
            if (inputBuffer == null)
                throw new ArgumentNullException("inputBuffer");
            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException("inputOffset");
            if (inputCount <= 0)
                throw new ArgumentOutOfRangeException("inputCount");
            if (inputCount % InputBlockSize != 0)
                throw new ArgumentOutOfRangeException("inputCount");
            if (inputCount > inputBuffer.Length - inputOffset)
                throw new ArgumentOutOfRangeException("inputCount");
            if (outputBuffer == null)
                throw new ArgumentNullException("outputBuffer");
            if (inputCount > outputBuffer.Length - outputOffset)
                throw new ArgumentOutOfRangeException("outputOffset");

            // If the transform can chain multiple blocks of data, then transform the input now.  Otherwise,
            // save it away to be transformed when TransformFinalBlock is called.
            if (CanChainBlocks)
            {
                byte[] transformed = null;
                try
                {
                    transformed = CngTransform(inputBuffer, inputOffset, inputCount);
                    Array.Copy(transformed, 0, outputBuffer, outputOffset, transformed.Length);
                    return transformed.Length;
                }
                finally
                {
                    if (transformed != null)
                    {
                        Array.Clear(transformed, 0, transformed.Length);
                    }
                }
            }
            else
            {
                m_inputBuffer.Write(inputBuffer, inputOffset, inputCount);
                return 0;
            }
        }

        /// <summary>
        ///     Transform the final block and finalize the encryption or decryption operation.
        /// </summary>
        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputBuffer == null)
                throw new ArgumentNullException("inputBuffer");
            if (inputOffset < 0)
                throw new ArgumentOutOfRangeException("inputOffset");
            if (inputCount < 0)
                throw new ArgumentOutOfRangeException("inputCount");
            if (inputCount > inputBuffer.Length - inputOffset)
                throw new ArgumentOutOfRangeException("inputCount");

            if (!m_transformedFinalBlock)
            {
                // Remove the chaining call flag, but retain the rest.
                m_authInfo.dwFlags &= ~BCryptNative.AuthenticatedCipherModeInfoFlags.ChainCalls;
                m_transformedFinalBlock = true;

                // If we cannot chain multiple blocks of data, then add the final block to the other input
                // blocks we've already collected, and use that to transform
                if (!CanChainBlocks)
                {
                    m_inputBuffer.Write(inputBuffer, inputOffset, inputCount);

                    // Reassign the input to be the full set of data that we've already gathered across all
                    // calls into the stream.
                    inputBuffer = m_inputBuffer.ToArray();
                    inputOffset = 0;
                    inputCount = inputBuffer.Length;
                }

                return CngTransform(inputBuffer, inputOffset, inputCount);
            }
            else
            {
                // We don't want to throw if we're re-flushing the final block, because if the crypto stream
                // was used in a try/finally block, and CngTransform throws an exception we'll end up
                // flushing again in the dispose.  That will end up covering the orginal exception with a
                // less useful re-flushing the final block exception.  Instead, make the call a no-op.
                return new byte[0];
            }
        }

        /// <summary>
        ///     Transform given blocks of data
        /// </summary>
        [SecurityCritical]
        [SecuritySafeCritical]
        private byte[] CngTransform(byte[] input, int inputOffset, int inputCount)
        {
            Debug.Assert(m_key != null, "key != null");
            Debug.Assert(!m_key.IsClosed && !m_key.IsInvalid, "!m_key.IsClosed && !m_key.IsInvalid");
            Debug.Assert(input != null, "input != null");
            Debug.Assert(inputOffset >= 0, "inputOffset >= 0");
            Debug.Assert(inputCount >= 0, "inputCount >= 0");
            Debug.Assert(inputCount <= input.Length - inputOffset, "inputCount <= input.Length - inputOffset");

            byte[] inputBuffer = null;
            try
            {
                // Build up a buffer of the only portion of the input we should be transforming
                inputBuffer = input;
                if (inputOffset > 0 || inputCount != input.Length)
                {
                    inputBuffer = new byte[inputCount];
                    Array.Copy(input, inputOffset, inputBuffer, 0, inputBuffer.Length);
                }

                if (m_encrypting)
                {
                    return BCryptNative.SymmetricEncrypt(m_key, inputBuffer, m_chainData, ref m_authInfo);
                }
                else
                {
                    return BCryptNative.SymmetricDecrypt(m_key, inputBuffer, this.m_chainData, ref m_authInfo);
                }
            }
            finally
            {
                if (inputBuffer != input)
                {
                    // Zeroize the input buffer if we allocated one
                    Array.Clear(inputBuffer, 0, inputBuffer.Length);
                }
            }
        }
    }
}
