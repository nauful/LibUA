// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq.Expressions;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Threading;
using LibUA.Security.Cryptography.Xml;

namespace LibUA.Security.Cryptography
{
    /// <summary>
    ///     <para>
    ///         .NET v3.5 added some new crypto algorithms in System.Core.dll, however due to layering
    ///         restrictions CryptoConfig does not have registration entries for these algorithms.  Similarly,
    ///         CryptoConfig does not know about any of the algorithms added in this assembly.
    ///     </para>
    ///     <para>
    ///         CryptoConfig2 wraps the CryptoConfig.Create method, allowing it to also create System.Core and
    ///         Microsoft.Security.Cryptography algorithm objects.
    ///     </para>
    ///     <para>
    ///         CryptoConfig2 requires the .NET Framework 3.5.
    ///     </para>
    /// </summary>
    public static class CryptoConfig2
    {
        private static readonly Dictionary<string, Type> s_algorithmMap = DefaultAlgorithmMap;
        private static readonly ReaderWriterLockSlim s_algorithmMapLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);

        /// <summary>
        ///     Default mapping of algorithm names to algorithm types
        /// </summary>
        private static Dictionary<string, Type> DefaultAlgorithmMap
        {
            get
            {
                Dictionary<string, Type> map = new Dictionary<string, Type>(StringComparer.OrdinalIgnoreCase);

                //
                // System.Core algorithms
                //

                AddAlgorithmToMap(map, typeof(AesCryptoServiceProvider), "AES");
                AddAlgorithmToMap(map, typeof(AesManaged));

                AddAlgorithmToMap(map, typeof(ECDsaCng), "ECDsa");

                AddAlgorithmToMap(map, typeof(ECDiffieHellmanCng), "ECDH", "ECDiffieHellman");

                AddAlgorithmToMap(map, typeof(MD5Cng));
                AddAlgorithmToMap(map, typeof(SHA1Cng));
                AddAlgorithmToMap(map, typeof(SHA256Cng));
                AddAlgorithmToMap(map, typeof(SHA256CryptoServiceProvider));
                AddAlgorithmToMap(map, typeof(SHA384Cng));
                AddAlgorithmToMap(map, typeof(SHA384CryptoServiceProvider));
                AddAlgorithmToMap(map, typeof(SHA512Cng));
                AddAlgorithmToMap(map, typeof(SHA512CryptoServiceProvider));

                //
                // Security.Cryptography algorithms
                //

                AddAlgorithmToMap(map, typeof(AesCng));
                AddAlgorithmToMap(map, typeof(AuthenticatedAesCng), "AuthenticatedAes", "AuthenticatedSymmetricAlgorithm");
                AddAlgorithmToMap(map, typeof(HMACSHA256Cng));
                AddAlgorithmToMap(map, typeof(HMACSHA384Cng));
                AddAlgorithmToMap(map, typeof(HMACSHA512Cng));
                AddAlgorithmToMap(map, typeof(RNGCng));
                AddAlgorithmToMap(map, typeof(RSACng));
                AddAlgorithmToMap(map, typeof(TripleDESCng));

                AddAlgorithmToMap(map, typeof(RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
                AddAlgorithmToMap(map, typeof(XmlDsigXPathWithNamespacesTransform));

                return map;
            }
        }

        /// <summary>
        ///     <para>
        ///         AddAlgorithm allows an application to register a new algorithm with CryptoConfig2 in the
        ///         current AppDomain. The algorithm is then creatable via calling
        ///         <see cref="CreateFromName" /> and supplying one of:
        ///     </para>
        ///     <list type="bullet">
        ///         <item>The name of the algorithm type</item>
        ///         <item>The namespace qualified name of the algorithm type</item>
        ///         <item>Any of the aliases supplied for the type</item>
        ///     </list>
        ///     <para>
        ///         This registration is valid only in the AppDomain that does the registration, and is not
        ///         persisted. The registered algorithm will only be creatable via CryptoConfig2 and not via
        ///         standard <see cref="CryptoConfig" />.
        ///     </para>
        ///     <para>
        ///         All algorithms registered with CryptoConfig2 must have a default constructor, or they wil
        ///          not be creatable at runtime.
        ///     </para>
        ///     <para>
        ///         This method is thread safe.
        ///     </para>
        /// </summary>
        /// <permission cref="PermissionSet">The immediate caller of this API must be fully trusted</permission>
        /// <param name="algorithm">type to register with CryptoConfig2</param>
        /// <param name="aliases">list of additional aliases which can create the type</param>
        /// <exception cref="ArgumentNullException">
        ///     if <paramref name="algorithm"/> or <paramref name="aliases"/> are null
        /// </exception>
        /// <exception cref="InvalidOperationException">
        ///     if an alias is either null, empty, or a duplicate of an existing registered alias
        /// </exception>
        [PermissionSet(SecurityAction.LinkDemand, Unrestricted = true)]
        [SecurityCritical]
        public static void AddAlgorithm(Type algorithm, params string[] aliases)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");
            if (aliases == null)
                throw new ArgumentNullException("aliases");

            s_algorithmMapLock.EnterWriteLock();
            try
            {
                // Make sure that we don't already have mappings for the input aliases - we want to eagerly
                // check for this rather than just letting the hash table insert fail so that the map doesn't
                // end up with some of the aliases added and others not added.
                // 
                // Note that we're explicitly not trying to protect against having the same alias added
                // multiple times via the same call to AddAlgorithm, since that problem is detectable by the
                // user of the API whereas detecting a conflict with another alias which had been previously
                // added cannot be reliably detected in the presense of multiple threads.
                foreach (string alias in aliases)
                {
                    if (String.IsNullOrEmpty(alias))
                    {
                        throw new InvalidOperationException("EmptyCryptoConfigAlias");
                    }

                    if (s_algorithmMap.ContainsKey(alias))
                    {
                        throw new InvalidOperationException("DuplicateCryptoConfigAlias");
                    }
                }

                AddAlgorithmToMap(s_algorithmMap, algorithm, aliases);
            }
            finally
            {
                s_algorithmMapLock.ExitWriteLock();
            }
        }

        /// <summary>
        ///     Add an algorithm to a given type map
        /// </summary>
        private static void AddAlgorithmToMap(Dictionary<string, Type> map, Type algorithm, params string[] aliases)
        {
            Debug.Assert(map != null, "map != null");
            Debug.Assert(algorithm != null, "algorithm != null");

            foreach (string alias in aliases)
            {
                Debug.Assert(!String.IsNullOrEmpty(alias), "!String.IsNullOrEmpty(alias)");
                map.Add(alias, algorithm);
            }

            if (!map.ContainsKey(algorithm.Name))
            {
                map.Add(algorithm.Name, algorithm);
            }

            if (!map.ContainsKey(algorithm.FullName))
            {
                map.Add(algorithm.FullName, algorithm);
            }
        }

        /// <summary>
        ///     <para>
        ///         CreateFactoryFromName is similar to <see cref="CreateFromName"/>, except that instead of
        ///         returning a single instance of a crypto algorithm, CreateFactoryFromName returns a
        ///         function that can create new instances of the algorithm.   This function will be more
        ///         efficient to use if multiple intsances of the same algorithm are needed than calling
        ///         CreateFromName repeatedly.
        ///     </para>
        ///     <para>
        ///         Name comparisons are case insensitive.
        ///     </para>
        ///     <para>
        ///         This method is thread safe.
        ///     </para>
        /// </summary>
        /// <param name="name">name of the algorithm to create a factory for</param>
        /// <exception cref="ArgumentNullException">if <paramref name="name"/> is null</exception>
        public static Func<object> CreateFactoryFromName(string name)
        {
            // Figure out what type of algorithm we need to create
            object algorithm = CreateFromName(name);
            if (algorithm == null)
            {
                return null;
            }

            Type algorithmType = algorithm.GetType();

            // Since we only need the algorithm type, rather than the full algorithm itself, we can clean up
            // the algorithm instance if it is disposable
            IDisposable disposableAlgorithm = algorithm as IDisposable;
            disposableAlgorithm?.Dispose();

            // Create a factory delegate which returns new instances of the algorithm type
            NewExpression algorithmCreationExpression = Expression.New(algorithmType);
            LambdaExpression creationFunction = Expression.Lambda<Func<object>>(algorithmCreationExpression);
            return creationFunction.Compile() as Func<object>;
        }

        /// <summary>
        ///     <para>
        ///         CreateFromName attempts to map the given algorithm name into an instance of the specified
        ///         algorithm. It works with both the built in algorithms in the .NET Framework 3.5 as well
        ///         as the algorithms in the Security.Cryptography.dll assembly. Since it does work with the
        ///         built in crypto types, CryptoConfig2.CreateFromName can be used as a drop-in replacement
        ///         for <see cref="CryptoConfig.CreateFromName(string)" />
        ///     </para>
        ///     <para>
        ///         Types in System.Core.dll and Security.Cryptography.dll can be mapped either by their
        ///         simple type name or their namespace type name. For example, AesCng and
        ///         Security.Cryptography.AesCng will both create an instance of the <see cref="AesCng" />
        ///         type. Additionally, the following names are also given mappings in CryptoConfig2:
        ///     </para>
        ///     <list type="bullet">
        ///         <item>AES - <see cref="AesCryptoServiceProvider" /></item>
        ///         <item>ECDsa - <see cref="ECDsaCng" /></item>
        ///         <item>ECDH - <see cref="ECDiffieHellmanCng" /></item>
        ///         <item>ECDiffieHellman - <see cref="ECDiffieHellmanCng" /></item>
        ///     </list>
        ///     <para>
        ///         Name comparisons are case insensitive.
        ///     </para>
        ///     <para>
        ///         This method is thread safe.
        ///     </para>
        /// </summary>
        /// <param name="name">name of the algorithm to create</param>
        /// <exception cref="ArgumentNullException">if <paramref name="name"/> is null</exception>
        public static object CreateFromName(string name)
        {
            if (name == null)
                throw new ArgumentNullException("name");

            // First try to use standard CryptoConfig to create the algorithm
            object cryptoConfigAlgorithm = CryptoConfig.CreateFromName(name);
            if (cryptoConfigAlgorithm != null)
            {
                return cryptoConfigAlgorithm;
            }

            // If we couldn't find the algorithm in crypto config, see if we have an internal mapping for
            // the name
            s_algorithmMapLock.EnterReadLock();
            try
            {
                if (s_algorithmMap.TryGetValue(name, out Type cryptoConfig2Type))
                {
                    return Activator.CreateInstance(cryptoConfig2Type);
                }
            }
            finally
            {
                s_algorithmMapLock.ExitReadLock();
            }

            // Otherwise we don't know how to create this type, so just return null
            return null;
        }
    }
}
