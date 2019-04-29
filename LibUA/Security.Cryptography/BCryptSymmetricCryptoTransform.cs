// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Security;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     Generic crypto transform, which implements symmetric encryption and decryption for algorithms
    ///     implemented in the BCrypt layer of CNG.  This type is used as the workhorse for the
    ///     BCryptSymmetricAlgorithm generic BCrypt symmetric algorithm implementation.
    /// </summary>
    internal sealed class BCryptSymmetricCryptoTransform : ICryptoTransform
    {
        private SafeBCryptAlgorithmHandle m_algorithm;
        private byte[] m_depadBuffer;
        private byte[] m_iv;
        private bool m_encrypting;
        private SafeBCryptKeyHandle m_key;
        private BlockPaddingMethod m_paddingMode;

        /// <summary>
        ///     Create an instance of an ICryptoTransform that can be used for BCrypt symmetric algorithms. 
        ///     
        ///     This object takes ownership of the algorithm handle passed in, and is responsible for
        ///     releasing it when it is no longer needed.  The algorithm handle should no longer be used by
        ///     other code once it is passed to this constructor.
        /// </summary>
        [SecurityCritical]
        internal BCryptSymmetricCryptoTransform(SafeBCryptAlgorithmHandle algorithm,
                                                byte[] key,
                                                byte[] iv,
                                                PaddingMode paddingMode,
                                                bool encrypting)
        {
            Debug.Assert(algorithm != null, "algorithm != null");
            Debug.Assert(!algorithm.IsClosed && !algorithm.IsInvalid, "!algorithm.IsClosed && !algorithm.IsInvalid");
            Debug.Assert(key != null, "key != null");

            m_algorithm = algorithm;
            m_encrypting = encrypting;

            m_paddingMode = BlockPaddingMethod.Create(paddingMode,
                                                      BCryptNative.GetInt32Property(algorithm, BCryptNative.ObjectPropertyName.BlockLength));
            m_iv = ProcessIV(iv, BCryptNative.GetInt32Property(algorithm,
                                                               BCryptNative.ObjectPropertyName.BlockLength),
                                                               BCryptNative.MapChainingMode(BCryptNative.GetStringProperty(algorithm, BCryptNative.ObjectPropertyName.ChainingMode)));
            m_key = BCryptNative.ImportSymmetricKey(algorithm, key);
        }

        //
        // ICryptoTransform implementation
        //

        public bool CanReuseTransform
        {
            get { return false; }
        }

        public bool CanTransformMultipleBlocks
        {
            get { return true; }
        }

        public int InputBlockSize
        {
            [SecurityCritical]
            [SecuritySafeCritical]
            get { return BCryptNative.GetInt32Property(m_algorithm, BCryptNative.ObjectPropertyName.BlockLength); }
        }

        public int OutputBlockSize
        {
            [SecurityCritical]
            [SecuritySafeCritical]
            get { return BCryptNative.GetInt32Property(m_algorithm, BCryptNative.ObjectPropertyName.BlockLength); }
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
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

            if (m_encrypting)
            {
                return EncryptBlocks(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            }
            else
            {
                return DecryptBlocks(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset, true);
            }
        }

        [SecurityCritical]
        [SecuritySafeCritical]
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

            if (m_encrypting)
            {
                // We need to pad the final block before encrypting it
                byte[] paddedBlock = m_paddingMode.PadBlock(inputBuffer, inputOffset, inputCount);
                if (paddedBlock.Length > 0)
                {
                    return BCryptNative.SymmetricEncrypt(m_key, m_iv, paddedBlock);
                }
                else
                {
                    return paddedBlock;
                }
            }
            else
            {
                // We can't decrypt a partial final block
                if (inputCount % InputBlockSize != 0)
                    throw new CryptographicException("CannotDecryptPartialBlock");

                // Decrypt all remaining data
                byte[] plaintext = new byte[inputCount + (m_depadBuffer != null ? m_depadBuffer.Length : 0)];
                int plaintextLength = DecryptBlocks(inputBuffer, inputOffset, inputCount, plaintext, 0, false);

                // Remove any padding 
                return m_paddingMode.DepadBlock(plaintext, 0, plaintextLength);
            }
        }

        [SecurityCritical]
        [SecuritySafeCritical]
        public void Dispose()
        {
            if (m_key != null)
            {
                m_key.Dispose();
            }

            if (m_algorithm != null)
            {
                m_algorithm.Dispose();
            }
        }

        /// <summary>
        ///     Decrypt ciphertext into plaintext without depadding the output
        /// </summary>
        [SecurityCritical]
        [SecuritySafeCritical]
        private int DecryptBlocks(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset, bool bufferLastBlock)
        {
            Debug.Assert(inputBuffer != null, "inputBuffer != null");
            Debug.Assert(inputOffset >= 0, "inputOffset >= 0");
            Debug.Assert(inputCount >= 0 && inputCount <= inputBuffer.Length - inputOffset, "inputCount >= 0 && inputCount <= inputBuffer.Length - inputOffset");
            Debug.Assert(inputCount % InputBlockSize == 0, "inputCount % InputBlockSize == 0");
            Debug.Assert(outputBuffer != null, "outputBuffer != null");
            Debug.Assert(inputCount <= outputBuffer.Length - outputOffset, "inputCount <= outputBuffer.Length - outputOffset");

            int decryptedBytes = 0;
            byte[] ciphertext = null;

            //
            // When decrypting, it's possible for us to be called with the final blocks of data in
            // TransformBlock, and then called with an empty TransformFinalBlock.  This means that we always
            // need to keep the last block of data we see in a depad buffer and not decrypt it until the
            // next TransformBlock or TransformFinalBlock is called.  Otherwise, we could end up decrypting
            // the padding bytes on the last call to TransformBlock and passing them out to our caller as
            // plaintext, when in fact we should have stripped them.
            //

            // If the padding cannot be removed, then we don't need to buffer the final block.
            if (!m_paddingMode.CanRemovePadding)
            {
                bufferLastBlock = false;
            }

            // If we've previously saved data to decrypt, we need to do that first.  Otherwise, we need
            // to allocate a buffer to save the last block of the incoming data in.
            if (m_depadBuffer != null)
            {
                byte[] decryptedDepad = BCryptNative.SymmetricDecrypt(m_key, m_iv, m_depadBuffer);
                Buffer.BlockCopy(decryptedDepad, 0, outputBuffer, outputOffset, decryptedDepad.Length);
                decryptedBytes += decryptedDepad.Length;
                outputOffset += decryptedDepad.Length;
            }

            // If we need to save the last block of data, do that now
            if (bufferLastBlock)
            {
                if (m_depadBuffer == null)
                {
                    m_depadBuffer = new byte[InputBlockSize];
                }

                // Copy the last block of data to the depad buffer, and decrypt the first blocks now.
                ciphertext = new byte[inputCount - m_depadBuffer.Length];
                Buffer.BlockCopy(inputBuffer, inputOffset, ciphertext, 0, ciphertext.Length);
                Buffer.BlockCopy(inputBuffer, inputOffset + inputCount - m_depadBuffer.Length, m_depadBuffer, 0, m_depadBuffer.Length);
            }
            else
            {
                // No depadding is necessary, so we can decrypt the entire input now
                m_depadBuffer = null;
                ciphertext = new byte[inputCount];
                Buffer.BlockCopy(inputBuffer, inputOffset, ciphertext, 0, ciphertext.Length);
            }

            // Decrypt the input that's not been saved in the depad buffer
            Debug.Assert(ciphertext != null, "ciphertext != null");
            if (ciphertext.Length > 0)
            {
                byte[] plaintext = BCryptNative.SymmetricDecrypt(m_key, m_iv, ciphertext);
                Buffer.BlockCopy(plaintext, 0, outputBuffer, outputOffset, plaintext.Length);
                decryptedBytes += plaintext.Length;
            }

            return decryptedBytes;
        }

        /// <summary>
        ///     Encrypt plaintext into ciphertext without applying padding
        /// </summary>
        [SecurityCritical]
        [SecuritySafeCritical]
        private int EncryptBlocks(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            Debug.Assert(inputBuffer != null, "inputBuffer != null");
            Debug.Assert(inputOffset >= 0, "inputOffset >= 0");
            Debug.Assert(inputCount >= 0 && inputCount <= inputBuffer.Length - inputOffset, "inputCount >= 0 && inputCount <= inputBuffer.Length - inputOffset");
            Debug.Assert(inputCount % InputBlockSize == 0, "inputCount % InputBlockSize == 0");
            Debug.Assert(outputBuffer != null, "outputBuffer != null");
            Debug.Assert(inputCount <= outputBuffer.Length - outputOffset, "inputCount <= outputBuffer.Length - outputOffset");

            // Pull the input into a stand alone array
            byte[] plaintext = new byte[inputCount];
            Buffer.BlockCopy(inputBuffer, inputOffset, plaintext, 0, plaintext.Length);

            // Do the encryption
            byte[] ciphertext = BCryptNative.SymmetricEncrypt(m_key, m_iv, plaintext);

            // Copy the output to the destination array
            Buffer.BlockCopy(ciphertext, 0, outputBuffer, outputOffset, ciphertext.Length);
            return ciphertext.Length;
        }

        /// <summary>
        ///     Process the user's IV into one that's acceptable to pass to BCrypt.
        ///     
        ///     We need to:
        ///       1. Make a copy of the IV so that it's not modified (BCrypt will modify the IV buffer on
        ///          calls to BCryptEncrypt / BCryptDecrypt, and we don't want the user's IV array to change).
        ///       2. Ensure we have an IV if we're not in ECB mode
        ///       3. Truncate the IV to the block size (for compatibility with v1.x)
        ///       4. Return null for ECB
        /// </summary>
        private static byte[] ProcessIV(byte[] iv, int blockSize, CipherMode mode)
        {
            byte[] realIV = null;

            if (mode != CipherMode.ECB)
            {
                if (iv != null)
                {
                    if (blockSize <= iv.Length)
                    {
                        realIV = new byte[blockSize];
                        Buffer.BlockCopy(iv, 0, realIV, 0, realIV.Length);
                    }
                    else
                    {
                        throw new CryptographicException("InvalidIVSize");
                    }
                }
                else
                {
                    throw new CryptographicException("MissingIV");
                }
            }

            return realIV;
        }
    }
}
