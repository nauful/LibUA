// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Security.Cryptography;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     Interface for crypto transforms that support generating an authentication tag.
    /// </summary>
    public interface IAuthenticatedCryptoTransform : ICryptoTransform2
    {
        /// <summary>
        ///     Get the authentication tag produced by the transform.  This is only valid in the encryption
        ///     case and only after the final block has been transformed.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        ///     If the crypto transform is a decryptor, or if the final block has not yet been transformed.
        /// </exception>
        byte[] GetTag();
    }
}
