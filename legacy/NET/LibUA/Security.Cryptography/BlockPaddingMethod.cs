// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

//
// This file contains the padding modes supported for block symmetric algorithms.  Each mode derives from
// the BlockPaddingMethod base class, and provides overrides that know how to apply padding from a block and
// remove the padding from blocks.
//

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     Base class for paddings to derive from
    /// </summary>
    internal abstract class BlockPaddingMethod
    {
        /// <summary>
        ///     Create a block padding method which can handle the given padding mode
        /// </summary>
        internal static BlockPaddingMethod Create(PaddingMode mode, int blockSize)
        {
            Debug.Assert(blockSize > 0, "blockSize > 0");

            switch (mode)
            {
                case PaddingMode.ANSIX923:
                    return new AnsiPadding(blockSize);
                case PaddingMode.ISO10126:
                    return new IsoPadding(blockSize);
                case PaddingMode.None:
                    return new NoPadding(blockSize);
                case PaddingMode.PKCS7:
                    return new PkcsPadding(blockSize);
                case PaddingMode.Zeros:
                    return new ZerosPadding(blockSize);
                default:
                    throw new ArgumentException("UnsupportedPaddingMode", "mode");
            }
        }

        private readonly int m_blockSize;

        protected BlockPaddingMethod(int blockSize)
        {
            Debug.Assert(blockSize > 0, "blockSize > 0");
            m_blockSize = blockSize;
        }

        /// <summary>
        ///     Size, in bytes, of blocks to pad
        /// </summary>
        protected int BlockSize
        {
            get { return m_blockSize; }
        }

        /// <summary>
        ///     Figure out the number of padding bytes to create
        /// </summary>
        protected int CountPaddingBytes(int blockBytes)
        {
            int paddingBytes = BlockSize - (blockBytes % BlockSize);
            if (!AddsExtraBlocks && paddingBytes == BlockSize)
            {
                paddingBytes = 0;
            }

            return paddingBytes;
        }

        /// <summary>
        ///     Does the padding method add an extra block to the end of the input if the input block does
        ///     not need any padding.
        /// </summary>
        protected abstract bool AddsExtraBlocks { get; }

        /// <summary>
        ///     Can the padding method be reversed to remove the padding on decryption.
        /// </summary>
        internal abstract bool CanRemovePadding { get; }

        /// <summary>
        ///     Apply padding to an input block.
        /// </summary>
        internal abstract byte[] PadBlock(byte[] block, int offset, int count);

        /// <summary>
        ///     Remove padding from a block
        /// </summary>
        internal abstract byte[] DepadBlock(byte[] block, int offset, int count);
    }

    /// <summary>
    ///     ANSI X923 padding fills the remaining block with zeros, with the final byte being the total
    ///     number of padding bytes added.  If the last block is already complete, a new block is added.
    ///     
    ///     xx 00 00 00 00 00 00 07
    /// </summary>
    internal sealed class AnsiPadding : BlockPaddingMethod
    {
        internal AnsiPadding(int blockSize) : base(blockSize) { }

        protected override bool AddsExtraBlocks
        {
            get { return true; }
        }

        internal override bool CanRemovePadding
        {
            get { return true; }
        }

        internal override byte[] PadBlock(byte[] block, int offset, int count)
        {
            int padBytes = CountPaddingBytes(count);

            byte[] result = new byte[count + padBytes];
            Buffer.BlockCopy(block, offset, result, 0, count);
            result[result.Length - 1] = (byte)padBytes;

            return result;
        }

        internal override byte[] DepadBlock(byte[] block, int offset, int count)
        {
            int padBytes = block[offset + count - 1];

            // Verify that the padding length seems correct
            if (padBytes <= 0 || padBytes > BlockSize)
            {
                throw new CryptographicException("InvalidPadding");
            }

            // Verify that all the padding bytes are zeros
            for (int i = offset + count - padBytes; i < offset + count - 1; ++i)
            {
                if (block[i] != 0)
                {
                    throw new CryptographicException("InvalidPadding");
                }
            }

            // Strip the padding
            byte[] result = new byte[count - padBytes];
            Buffer.BlockCopy(block, offset, result, 0, result.Length);
            return result;
        }
    }

    /// <summary>
    ///     ISO 10126 padding fills the remaining block with random bytes, with the final byte being the total
    ///     number of padding bytes added.  If the last block is already complete, a new block is added.
    ///     
    ///     xx rr rr rr rr rr rr 07
    /// </summary>
    internal sealed class IsoPadding : BlockPaddingMethod
    {
        internal IsoPadding(int blockSize) : base(blockSize) { }

        protected override bool AddsExtraBlocks
        {
            get { return true; }
        }

        internal override bool CanRemovePadding
        {
            get { return true; }
        }

        internal override byte[] PadBlock(byte[] block, int offset, int count)
        {
            int padBytes = CountPaddingBytes(count);

            byte[] result = new byte[count + padBytes];
            RNGCng.StaticRng.GetBytes(result);
            Buffer.BlockCopy(block, offset, result, 0, count);
            result[result.Length - 1] = (byte)padBytes;

            return result;
        }

        internal override byte[] DepadBlock(byte[] block, int offset, int count)
        {
            int padBytes = block[offset + count - 1];

            // Verify that the padding length seems correct
            if (padBytes <= 0 || padBytes > BlockSize)
            {
                throw new CryptographicException("InvalidPadding");
            }

            // Strip the padding
            byte[] result = new byte[count - padBytes];
            Buffer.BlockCopy(block, offset, result, 0, result.Length);
            return result;
        }
    }

    /// <summary>
    ///     None padding does not add or remove anything from the input text.  This implies that the input
    ///     plaintext must already be a multiple of the block size.
    /// </summary>
    internal sealed class NoPadding : BlockPaddingMethod
    {
        internal NoPadding(int blockSize) : base(blockSize) { }

        protected override bool AddsExtraBlocks
        {
            get { return false; }
        }

        internal override bool CanRemovePadding
        {
            get { return false; }
        }

        internal override byte[] PadBlock(byte[] block, int offset, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(block, offset, result, 0, result.Length);
            return result;
        }

        internal override byte[] DepadBlock(byte[] block, int offset, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(block, offset, result, 0, result.Length);
            return result;
        }
    }

    /// <summary>
    ///     PKCS7 padding fills up the remainder of the block with bytes which are the same value as the
    ///     number of padding bytes applied.  If the last block is already complete, a new block is added.
    ///     
    ///     xx 07 07 07 07 07 07 07
    /// </summary>
    internal sealed class PkcsPadding : BlockPaddingMethod
    {
        internal PkcsPadding(int blockSize) : base(blockSize) { }

        protected override bool AddsExtraBlocks
        {
            get { return true; }
        }

        internal override bool CanRemovePadding
        {
            get { return true; }
        }

        internal override byte[] PadBlock(byte[] block, int offset, int count)
        {
            int padBytes = CountPaddingBytes(count);

            byte[] result = new byte[count + padBytes];
            Buffer.BlockCopy(block, offset, result, 0, count);

            for (int i = count; i < result.Length; ++i)
            {
                result[i] = (byte)padBytes;
            }

            return result;
        }

        internal override byte[] DepadBlock(byte[] block, int offset, int count)
        {
            int padBytes = block[offset + count - 1];

            // Verify that the padding length seems correct
            if (padBytes <= 0 || padBytes > BlockSize)
            {
                throw new CryptographicException("InvalidPadding");
            }

            // Verify that all the padding bytes are the padding count
            for (int i = offset + count - padBytes; i < offset + count; ++i)
            {
                if (block[i] != (int)padBytes)
                {
                    throw new CryptographicException("InvalidPadding");
                }
            }

            // Strip the padding
            byte[] result = new byte[count - padBytes];
            Buffer.BlockCopy(block, offset, result, 0, result.Length);
            return result;
        }
    }

    /// <summary>
    ///     Zeros padding fills out the final block with 0 bytes. It does not add an extra block if the
    ///     final block is already complete.  Note that since we cannot tell if the plaintext ends in a 00
    ///     byte, or if that byte is part of the padding, zeros padding cannot be removed.
    ///     
    ///     xx 00 00 00 00 00 00 00
    /// </summary>
    internal sealed class ZerosPadding : BlockPaddingMethod
    {
        internal ZerosPadding(int blockSize) : base(blockSize) { }

        protected override bool AddsExtraBlocks
        {
            get { return false; }
        }

        internal override bool CanRemovePadding
        {
            get { return false; }
        }

        internal override byte[] PadBlock(byte[] block, int offset, int count)
        {
            byte[] result = new byte[count + CountPaddingBytes(count)];
            Buffer.BlockCopy(block, offset, result, 0, count);
            return result;
        }

        internal override byte[] DepadBlock(byte[] block, int offset, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(block, offset, result, 0, result.Length);
            return result;
        }
    }
}
