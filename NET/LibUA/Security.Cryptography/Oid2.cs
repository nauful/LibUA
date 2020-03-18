// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     <para>
    ///         Oid2 is an enhanced OID type over the <see cref="Oid" /> type.  Oid2 provides some
    ///         performance benefits when it is used to lookup OID information since it can do more directed
    ///         queries than Oid does.  It also exposes additional information about the OID, such as group
    ///         and algortihm mappings for CAPI and CNG.
    ///     </para>
    ///     <para>
    ///         One notable difference between Oid2 and Oid is that Oid2 will never query for information
    ///         about an Oid unless specifically instructed to via a call to EnumerateOidInformation or one of
    ///         the FindBy methods. Simply constructing an Oid2 type does not trigger a lookup on information
    ///         not provided.
    ///     </para>
    /// </summary>
    public sealed class Oid2
    {
        private string m_oid;
        private string m_name;
        private OidGroup m_group;

        // Algorithm identifiers for both CAPI and CNG for CRYPT_*_ALG_OID_GROUP_ID OIDs
        private int? m_algorithmId;
        private CngAlgorithm m_cngAlgorithm;    
        private CngAlgorithm m_cngExtraAlgorithm;

        /// <summary>
        ///     Constructs an Oid2 object with the given value and friendly name. No lookup is done for
        ///     further information on this OID. It is assigned a group of AllGroups and no algorithm mapping.
        /// </summary>
        /// <param name="oid">value of this OID</param>
        /// <param name="friendlyName">friendly name for the OID</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="oid" /> or <paramref name="friendlyName"/> are null
        /// </exception>
        public Oid2(string oid, string friendlyName)
            : this(oid, friendlyName, OidGroup.AllGroups)
        {
            return;
        }

        /// <summary>
        ///     Constructs an Oid2 object with the given value and friendly name belonging to a specific
        ///     group. No lookup is done for further information on this OID. It has no algorithm mapping.
        /// </summary>
        /// <param name="oid">value of this OID</param>
        /// <param name="friendlyName">friendly name for the OID</param>
        /// <param name="group">group the OID belongs to</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="oid" /> or <paramref name="friendlyName"/> are null
        /// </exception>
        public Oid2(string oid, string friendlyName, OidGroup group)
            : this (oid, friendlyName, group, null, null)
        {
            return;
        }

        /// <summary>
        ///     Constructs an Oid2 object with the given value and friendly name belonging to a specific
        ///     group. No lookup is done for further information on this OID. It has no CAPI algorithm
        ///     mapping, but does have optional CNG algorithm mappings.
        /// </summary>
        /// <param name="oid">value of this OID</param>
        /// <param name="friendlyName">friendly name for the OID</param>
        /// <param name="group">group the OID belongs to</param>
        /// <param name="cngAlgorithm">CNG algorithm that this OID represents</param>
        /// <param name="extraCngAlgorithm">additional CNG algorithm this OID represents</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="oid" /> or <paramref name="friendlyName"/> are null
        /// </exception>
        public Oid2(string oid,
                    string friendlyName,
                    OidGroup group,
                    CngAlgorithm cngAlgorithm,
                    CngAlgorithm extraCngAlgorithm)
        {
            if (oid == null)
                throw new ArgumentNullException("oid");
            if (friendlyName == null)
                throw new ArgumentNullException("friendlyName");

            m_oid = oid;
            m_name = friendlyName;
            m_group = group;
            m_cngAlgorithm = cngAlgorithm;
            m_cngExtraAlgorithm = extraCngAlgorithm;
        }

        /// <summary>
        ///     Constructs an Oid2 object with the given value and friendly name belonging to a specific
        ///     group. No lookup is done for further information on this OID. It has both a CAPI algorithm
        ///     mapping and optional CNG algorithm mappings.
        /// </summary>
        /// <param name="oid">value of this OID</param>
        /// <param name="friendlyName">friendly name for the OID</param>
        /// <param name="group">group the OID belongs to</param>
        /// <param name="capiAlgorithm">CAPI algorithm ID that this OID represents</param>
        /// <param name="cngAlgorithm">CNG algorithm that this OID represents</param>
        /// <param name="extraCngAlgorithm">additional CNG algorithm this OID represents</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="oid" /> or <paramref name="friendlyName"/> are null
        /// </exception>
        public Oid2(string oid,
                    string friendlyName,
                    OidGroup group,
                    int capiAlgorithm,
                    CngAlgorithm cngAlgorithm,
                    CngAlgorithm extraCngAlgorithm)
        {
            if (oid == null)
                throw new ArgumentNullException("oid");
            if (friendlyName == null)
                throw new ArgumentNullException("friendlyName");

            m_oid = oid;
            m_name = friendlyName;
            m_group = group;
            m_algorithmId = capiAlgorithm;
            m_cngAlgorithm = cngAlgorithm;
            m_cngExtraAlgorithm = extraCngAlgorithm;
        }

        /// <summary>
        ///     Unpack a CAPI CRYPT_OID_INFO structure into an Oid2
        /// </summary>
        private Oid2(CapiNative.CRYPT_OID_INFO oidInfo)
        {
            m_oid = oidInfo.pszOID ?? String.Empty;
            m_name = oidInfo.pwszName ?? String.Empty;
            m_group = oidInfo.dwGroupId;

            // Algorithm information is only set for specific OID groups
            if (oidInfo.dwGroupId == OidGroup.EncryptionAlgorithm ||
                oidInfo.dwGroupId == OidGroup.HashAlgorithm ||
                oidInfo.dwGroupId == OidGroup.PublicKeyAlgorithm ||
                oidInfo.dwGroupId == OidGroup.SignatureAlgorithm)
            {
                // Values of 0 or -1 indicate that there is no CAPI algorithm mapping
                if (oidInfo.dwValue != 0 && oidInfo.dwValue != -1)
                {
                    m_algorithmId = oidInfo.dwValue;
                }

                if (!String.IsNullOrEmpty(oidInfo.pwszCNGAlgid))
                {
                    m_cngAlgorithm = new CngAlgorithm(oidInfo.pwszCNGAlgid);
                }

                if (!String.IsNullOrEmpty(oidInfo.pwszCNGExtraAlgid))
                {
                    m_cngExtraAlgorithm = new CngAlgorithm(oidInfo.pwszCNGExtraAlgid);
                }
            }
        }

        //
        // Acccessor properties
        //

        /// <summary>
        ///     Get the CAPI algorithm ID represented by this OID.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        ///     if HasAlgorithmId is false
        /// </exception>
        public int AlgorithmId
        {
            get { return m_algorithmId.Value; }
        }

        /// <summary>
        ///     Get the CNG algorithm that this OID represents.
        /// </summary>
        public CngAlgorithm CngAlgorithm
        {
            get { return m_cngAlgorithm; }
        }

        /// <summary>
        ///     Get an additional CNG algorithm that this OID represents.
        /// </summary>
        public CngAlgorithm CngExtraAlgorithm
        {
            get { return m_cngExtraAlgorithm; }
        }

        /// <summary>
        ///     Get the friendly name of the OID.
        /// </summary>
        public string FriendlyName
        {
            get { return m_name; }
        }

        /// <summary>
        ///     Get the OID group that this OID belongs to.
        /// </summary>
        public OidGroup Group
        {
            get { return m_group; }
        }

        /// <summary>
        ///     Determines if the OID has a CAPI algorithm ID that it maps to, available in the AlgorithmId
        ///     property. This property does not check to see if the OID has matching CNG algorithms, which
        ///     can be checked by checking the CngAlgorithm property for null.
        /// </summary>
        public bool HasAlgorithmId
        {
            get { return m_algorithmId.HasValue; }
        }

        /// <summary>
        ///     Get the string representation of the OID.
        /// </summary>
        public string Value
        {
            get { return m_oid; }
        }

        //
        // Utility methods
        //

        /// <summary>
        ///     This overload of EnumerateOidInformation returns an enumerator containing an Oid2 object for
        ///     every OID registered regardless of group.
        /// </summary>
        public static IEnumerable<Oid2> EnumerateOidInformation()
        {
            return EnumerateOidInformation(OidGroup.AllGroups);
        }

        /// <summary>
        ///     This overload of EnumerateOidInformation returns an enumerator containing an Oid2 object for
        ///     every OID registered as belonging to a specific OID group.
        /// </summary>
        /// <param name="group">OID group to enumerate, AllGroups to enumerate every OID</param>
        [SecurityCritical]
        [SecuritySafeCritical]
        public static IEnumerable<Oid2> EnumerateOidInformation(OidGroup group)
        {
            foreach (CapiNative.CRYPT_OID_INFO oidInfo in CapiNative.EnumerateOidInformation(group))
            {
                yield return new Oid2(oidInfo);
            }
        }

        /// <summary>
        ///     This overload of FindByFriendlyName searches for any OID registered on the local machine with
        ///     the specified friendly name. It looks in all OID groups for an OID matching the name, but does
        ///     not look in the Active Directory for a matching OID. If no match is found, null is returned.
        /// </summary>
        /// <param name="friendlyName">name of the OID to search for</param>
        public static Oid2 FindByFriendlyName(string friendlyName)
        {
            return FindByFriendlyName(friendlyName, OidGroup.AllGroups);
        }

        /// <summary>
        ///     This overload of FindByFriendlyName searches for any OID registered on the local machine with
        ///     the specified friendly name. It looks only in the specified OID groups for an OID matching the
        ///     name, and does not look in the Active Directory for a matching OID. If no match is found, null
        ///     is returned.
        /// </summary>
        /// <param name="friendlyName">name of the OID to search for</param>
        /// <param name="group">OID group to enumerate, AllGroups to enumerate every OID</param>
        public static Oid2 FindByFriendlyName(string friendlyName, OidGroup group)
        {
            return FindByFriendlyName(friendlyName, group, false);
        }

        /// <summary>
        ///     This overload of FindByFriendlyName searches for any OID registered on the local machine with
        ///     the specified friendly name. It looks only in the specified OID groups for an OID matching the
        ///     name, and can optionally look in the Active Directory for a matching OID. If no match is
        ///     found, null is returned.
        /// </summary>
        /// <param name="friendlyName">name of the OID to search for</param>
        /// <param name="group">OID group to enumerate, AllGroups to enumerate every OID</param>
        /// <param name="useNetworkLookup">
        ///     true to look in the Active Directory for a match, false to skip network lookup
        /// </param>
        [SecurityCritical]
        [SecuritySafeCritical]
        public static Oid2 FindByFriendlyName(string friendlyName, OidGroup group, bool useNetworkLookup)
        {
            CapiNative.CRYPT_OID_INFO oidInfo = new CapiNative.CRYPT_OID_INFO();
            if (CapiNative.TryFindOidInfo(friendlyName, group, CapiNative.OidKeyType.Name, useNetworkLookup, out oidInfo))
            {
                return new Oid2(oidInfo);
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        ///     This overload of FindByValue searches for any OID registered on the local machine with the
        ///     specified OID value. It looks in all OID groups for an OID matching the value, but does not
        ///     look in the Active Directory for a matching OID. If no match is found, null is returned.
        /// </summary>
        /// <param name="oid">oid to search for</param>
        public static Oid2 FindByValue(string oid)
        {
            return FindByValue(oid, OidGroup.AllGroups);
        }

        /// <summary>
        ///     This overload of FindByValue searches for any OID registered on the local machine with the
        ///     specified value. It looks only in the specified OID groups for an OID matching the value, and
        ///     does not look in the Active Directory for a matching OID. If no match is found, null is
        ///     returned.
        /// </summary>
        /// <param name="oid">oid to search for</param>
        /// <param name="group">OID group to enumerate, AllGroups to enumerate every OID</param>
        public static Oid2 FindByValue(string oid, OidGroup group)
        {
            return FindByValue(oid, group, false);
        }

        /// <summary>
        ///     This overload of FindByValue searches for any OID registered on the local machine with the
        ///     specified value. It looks only in the specified OID groups for an OID matching the value, and
        ///     can optionally look in the Active Directory for a matching OID. If no match is found, null is
        ///     returned.
        /// </summary>
        /// <param name="oid">oid to search for</param>
        /// <param name="group">OID group to enumerate, AllGroups to enumerate every OID</param>
        /// <param name="useNetworkLookup">
        ///     true to look in the Active Directory for a match, false to skip network lookup
        /// </param>
        [SecurityCritical]
        [SecuritySafeCritical]
        public static Oid2 FindByValue(string oid, OidGroup group, bool useNetworkLookup)
        {
            CapiNative.CRYPT_OID_INFO oidInfo = new CapiNative.CRYPT_OID_INFO();
            if (CapiNative.TryFindOidInfo(oid, group, CapiNative.OidKeyType.Oid, useNetworkLookup, out oidInfo))
            {
                return new Oid2(oidInfo);
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        ///     Register the OID on the local machine, so that later processes can query for the OID and
        ///     include it in enumerations. This method requires that the caller be fully trusted, and that
        ///     the user context that the calling application be run under be an Administrator on the machine.
        ///     Updating the registration table may have no effect on the current process, if Windows has
        ///     already read them. Instead, the process may need to be restarted to reflect the registration
        ///     changes. This overload of Register places the OID after the built in OIDs.
        /// </summary>
        /// <permission cref="PermissionSet">The immediate caller of this API must be fully trusted</permission>
        [SecurityCritical]
        [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        public void Register()
        {
            Register(OidRegistrationOptions.None);
        }

        /// <summary>
        ///     Register the OID on the local machine, so that later processes can query for the OID and
        ///     include it in enumerations. This method requires that the caller be fully trusted, and that
        ///     the user context that the calling application be run under be an Administrator on the machine.
        ///     Updating the registration table may have no effect on the current process, if Windows has
        ///     already read them. Instead, the process may need to be restarted to reflect the registration
        ///     changes. This overload of Register can places the OID either before or after the built in OIDs
        ///     depending on the registration options.
        /// </summary>
        /// <permission cref="PermissionSet">The immediate caller of this API must be fully trusted</permission>
        /// <param name="registrationOptions">settings to register the OID with</param>
        [SecurityCritical]
        [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        public void Register(OidRegistrationOptions registrationOptions)
        {
            CapiNative.RegisterOid(ToOidInfo(), registrationOptions);
        }

        /// <summary>
        ///     <para>
        ///         On Windows 2003, the default OID -> algorithm ID mappings for the SHA2 family of hash
        ///         algorithms are not setup in a way that the .NET Framework v3.5 SP1 can understand them
        ///         when creating RSA-SHA2 signatures. This method can be used to update the registrations on
        ///         Windows 2003 so that RSA-SHA2 signatures work as expected.
        ///    </para>
        ///    <para>
        ///         To call this method, the calling code must be fully trusted and running as an
        ///         Administrator on the machine. If OID tables have already been read for the process, then
        ///         the process may need to be restarted for the registration to take effect. Therefore, it is
        ///         recommended to use this method in a setup program or as the first line of code in your
        ///         application.
        ///     </para>
        ///     <para>
        ///         While not required, this method will work on other versions of Windows and the .NET
        ///         Framework. 
        ///     </para>
        /// </summary>
        /// <permission cref="PermissionSet">This API requires that its immediate caller be fully trusted</permission>
        [SecurityCritical]
        [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        public static void RegisterSha2OidInformationForRsa()
        {
            // On Windows 2003, the default ALGID -> OID mapping for the SHA2 comes back with an unknown
            // ALG_ID of 0.  The v2.0 CLR however expects unknown ALG_IDs to be mapped to -1, and therefore
            // fails to map this unknown value to the correct SHA-256 ALG_ID.  If we're on Windows 2003 and
            // CLR 2.0, we'll re-register the SHA-256 OID so that the CLR can pick it up.
            if (Environment.OSVersion.Platform == PlatformID.Win32NT &&
                Environment.OSVersion.Version.Major == 5 &&
                Environment.OSVersion.Version.Minor == 2 &&
                Environment.Version.Major == 2)
            {
                Oid2[] sha2Oids = new Oid2[]
                {
                    new Oid2(CapiNative.WellKnownOids.Sha256, "sha256", OidGroup.HashAlgorithm, (int)CapiNative.AlgorithmID.Sha256, CngAlgorithm.Sha256, null),
                    new Oid2(CapiNative.WellKnownOids.Sha384, "sha384", OidGroup.HashAlgorithm, (int)CapiNative.AlgorithmID.Sha384, CngAlgorithm.Sha384, null),
                    new Oid2(CapiNative.WellKnownOids.Sha512, "sha512", OidGroup.HashAlgorithm, (int)CapiNative.AlgorithmID.Sha512, CngAlgorithm.Sha512, null)
                };

                foreach (Oid2 sha2Oid in sha2Oids)
                {
                    // If the OID is currently registered to an ALG_ID other than 0, we don't want to break
                    // that registration (or duplicate it) by overwriting our own.
                    Oid2 currentOid = Oid2.FindByValue(sha2Oid.Value, sha2Oid.Group, false);

                    if (currentOid == null || !currentOid.HasAlgorithmId || currentOid.AlgorithmId == 0)
                    {
                        // There is either no current OID registration for the algorithm, or it contains a
                        // CAPI algorithm mapping which will not be understood by the v2.0 CLR.  Register a
                        // new mapping which will have the CAPI algorithm ID in it.
                        sha2Oid.Register(OidRegistrationOptions.InstallBeforeDefaultEntries);
                    }
                }
            }
        }

        /// <summary>
        ///     Convert the Oid2 object into an Oid object that is usable by APIs in the .NET Framework which
        ///     expect an Oid rather than an Oid2. This method only transfers the OID value and friendly name
        ///     to the new Oid object. Group and algorithm mappings are lost.
        /// </summary>
        public Oid ToOid()
        {
            return new Oid(m_oid, m_name);
        }

        /// <summary>
        ///     Convert an Oid2 into a CAPI OID_INFO
        /// </summary>
        [SecurityCritical]
        [SecuritySafeCritical]
        private CapiNative.CRYPT_OID_INFO ToOidInfo()
        {
            CapiNative.CRYPT_OID_INFO oidInfo = new CapiNative.CRYPT_OID_INFO();
            oidInfo.cbSize = Marshal.SizeOf(typeof(CapiNative.CRYPT_OID_INFO));
            oidInfo.pszOID = m_oid;
            oidInfo.pwszName = m_name;
            oidInfo.dwGroupId = m_group;

            if (m_algorithmId.HasValue)
            {
                oidInfo.dwValue = m_algorithmId.Value;
            }

            if (m_cngAlgorithm != null)
            {
                oidInfo.pwszCNGAlgid = m_cngAlgorithm.Algorithm;
            }

            if (m_cngExtraAlgorithm != null)
            {
                oidInfo.pwszCNGExtraAlgid = m_cngExtraAlgorithm.Algorithm;
            }

            return oidInfo;
        }

        /// <summary>
        ///     Revert the registration of this OID, which may have been registered with one of the Register
        ///     overloads. As with OID registration, this method requires that the caller be fully trusted,
        ///     and that the user context that the calling application be run under be an Administrator on the
        ///     machine. Updating the registration table may have no effect on the current process, if Windows
        ///     has already read them. Instead, the process may need to be restarted to reflect the
        ///     registration changes.
        /// </summary>
        /// <permission cref="PermissionSet">This API requires that its immediate caller be fully trusted</permission>
        [SecurityCritical]
        [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        public void Unregister()
        {
            CapiNative.UnregisterOid(ToOidInfo());
        }
    }
}
