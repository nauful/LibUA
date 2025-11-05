// Copyright (c) Microsoft Corporation.  All rights reserved.

using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     Interface for algorithms implemented over the CNG layer of Windows to provide CNG implementation
    ///     details through.
    /// </summary>
    public interface ICngAlgorithm
    {
        /// <summary>
        ///     Gets the algorithm or key storage provider being used for the implementation of the CNG
        ///     algorithm.
        /// </summary>
        CngProvider Provider { get; }
    }
}
