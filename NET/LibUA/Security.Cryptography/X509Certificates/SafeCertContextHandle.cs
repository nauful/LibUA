// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;

namespace LibUA.Security.Cryptography.X509Certificates
{
    /// <summary>
    ///     <para>
    ///         SafeCertContextHandle provides a SafeHandle class for an X509Certificate's certificate context
    ///         as stored in its <see cref="System.Security.Cryptography.X509Certificates.X509Certificate.Handle" />
    ///         property.  This can be used instead of the raw IntPtr to avoid races with the garbage
    ///         collector, ensuring that the X509Certificate object is not cleaned up from underneath you
    ///         while you are still using the handle pointer.
    ///     </para>
    ///     <para>
    ///         This safe handle type represents a native CERT_CONTEXT.
    ///         (http://msdn.microsoft.com/en-us/library/aa377189.aspx)
    ///     </para>
    ///     <para>
    ///         A SafeCertificateContextHandle for an X509Certificate can be obtained by calling the <see
    ///         cref="X509CertificateExtensionMethods.GetCertificateContext" /> extension method.
    ///     </para>
    /// </summary>
    /// <permission cref="SecurityPermission">
    ///     The immediate caller must have SecurityPermission/UnmanagedCode to use this type.
    /// </permission>
    [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
    public sealed class SafeCertContextHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeCertContextHandle() : base(true)
        {
        }

        [DllImport("crypt32.dll")]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressMessage("Microsoft.Design", "CA1060:MovePInvokesToNativeMethodsClass", Justification = "SafeHandle release method")]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CertFreeCertificateContext(IntPtr pCertContext);

        protected override bool ReleaseHandle()
        {
            return CertFreeCertificateContext(handle);
        }
    }
}
