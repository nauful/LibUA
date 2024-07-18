// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     Extended crypto transform interface which provides extra information about the capabilities of a
    ///     specific transform.
    /// </summary>
    public interface ICryptoTransform2 : ICryptoTransform
    {
        /// <summary>
        ///     <para>
        ///         Can the transform be used in a chained mode - where it is invoked multiple times before
        ///         the final ciphertext and tag are retrieved.  (For example, can it transform each block in
        ///         the input in seperate calls, or must they all come in through a single call.)
        ///     </para>
        ///     <para>
        ///         This is different from CanTransformMultipleBlocks in that CanTransformMultipleBlocks
        ///         indicates if a transform can handle multiple blocks of input in a single call, while
        ///         CanChainBlocks indicates if a transform can chain multiple blocks of input across multiple
        ///         calls to TransformBlock/TransformFinalBlock.
        ///     </para>
        /// </summary>
        bool CanChainBlocks { get; }
    }
}
