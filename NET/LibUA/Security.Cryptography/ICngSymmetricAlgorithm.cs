// Copyright (c) Microsoft Corporation.  All rights reserved.

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     Interface for symmetric algorithms implemented over the CNG layer of Windows to provide CNG
    ///     implementation details through.
    /// </summary>
    public interface ICngSymmetricAlgorithm : ICngAlgorithm
    {
        /// <summary>
        ///     Get or set the CNG chaining mode the algorithm is using.
        /// </summary>
        CngChainingMode CngMode { get; set; }
    }
}
