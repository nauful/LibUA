using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Timers;
using LibUA;
using LibUA.Core;
using LibUA.Server;
using Microsoft.Extensions.Logging;

namespace TestServer
{
    internal class Program
    {
        private class DemoApplication : LibUA.Server.Application
        {
            private readonly ApplicationDescription uaAppDesc;
            private readonly NodeObject ItemsRoot;
            private readonly NodeVariable[] TrendNodes;
            private readonly NodeVariable Node1D, Node2D;
            private X509Certificate2 appCertificate = null;
            private RSA cryptPrivateKey = null;

            public override X509Certificate2 ApplicationCertificate
            {
                get { return appCertificate; }
            }

            public override RSA ApplicationPrivateKey
            {
                get { return cryptPrivateKey; }
            }

            public DemoApplication()
            {
                LoadCertificateAndPrivateKey();

                uaAppDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Server,
                    null, null, null);

                ItemsRoot = new NodeObject(new NodeId(2, 0), new QualifiedName("Items"), new LocalizedText("Items"),
                    new LocalizedText("Items"), 0, 0, 0);

                // Objects organizes Items
                AddressSpaceTable[new NodeId(UAConst.ObjectsFolder)].References
                    .Add(new ReferenceNode(new NodeId(UAConst.Organizes), new NodeId(2, 0), false));
                ItemsRoot.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes),
                    new NodeId(UAConst.ObjectsFolder), true));
                AddressSpaceTable.TryAdd(ItemsRoot.Id, ItemsRoot);

                TrendNodes = new NodeVariable[1000];
                var nodeTypeFloat = new NodeId(0, 10);
                for (int i = 0; i < TrendNodes.Length; i++)
                {
                    var id = string.Format("Trend {0}", (1 + i).ToString("D6"));
                    TrendNodes[i] = new NodeVariable(new NodeId(2, (uint)(1 + i)), new QualifiedName(id),
                        new LocalizedText(id), new LocalizedText(id), 0, 0,
                        AccessLevel.CurrentRead | AccessLevel.HistoryRead,
                        AccessLevel.CurrentRead | AccessLevel.HistoryRead, 0, true, nodeTypeFloat);

                    ItemsRoot.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), TrendNodes[i].Id, false));
                    TrendNodes[i].References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), ItemsRoot.Id, true));
                    AddressSpaceTable.TryAdd(TrendNodes[i].Id, TrendNodes[i]);
                }

                Node1D = new NodeVariable(new NodeId(2, (uint)(1000 + 1)), new QualifiedName("Array - 1D"),
                        new LocalizedText("Array - 1D"), new LocalizedText("Array - 1D"), 0, 0,
                        AccessLevel.CurrentRead, AccessLevel.CurrentRead, 0, false, nodeTypeFloat, ValueRank.OneDimension);
                Node2D = new NodeVariable(new NodeId(2, (uint)(1000 + 2)), new QualifiedName("Array - 2D"),
                        new LocalizedText("Array - 2D"), new LocalizedText("Array - 2D"), 0, 0,
                        AccessLevel.CurrentRead, AccessLevel.CurrentRead, 0, false, nodeTypeFloat, ValueRank.OneOrMoreDimensions);

                ItemsRoot.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), Node1D.Id, false));
                Node1D.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), ItemsRoot.Id, true));
                AddressSpaceTable.TryAdd(Node1D.Id, Node1D);

                ItemsRoot.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), Node2D.Id, false));
                Node2D.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), ItemsRoot.Id, true));
                AddressSpaceTable.TryAdd(Node2D.Id, Node2D);
            }

            public override object SessionCreate(SessionCreationInfo sessionInfo)
            {
                // Optionally create and return a session object with sessionInfo if you want to track that same object
                // when the client validates its session (anonymous, username + password or certificate).

                return null;
            }

            public override bool SessionValidateClientApplication(object session,
                ApplicationDescription clientApplicationDescription, byte[] clientCertificate, string sessionName)
            {
                // Update your session object with the client's UA application description
                // Return true to allow the client, false to reject

                return true;
            }

            public override void SessionRelease(object session)
            {
            }

            public override bool SessionValidateClientUser(object session, object userIdentityToken)
            {
                if (userIdentityToken is UserIdentityAnonymousToken)
                {
                    return true;
                }
                else if (userIdentityToken is UserIdentityUsernameToken)
                {
                    _ = (userIdentityToken as UserIdentityUsernameToken).Username;
                    _ =
                        (new UTF8Encoding()).GetString((userIdentityToken as UserIdentityUsernameToken).PasswordHash);

                    return true;
                }

                throw new Exception("Unhandled user identity token type");
            }

            private ApplicationDescription CreateApplicationDescriptionFromEndpointHint(string endpointUrlHint)
            {
                string[] discoveryUrls = uaAppDesc.DiscoveryUrls;
                if (discoveryUrls == null && !string.IsNullOrEmpty(endpointUrlHint))
                {
                    discoveryUrls = new string[] { endpointUrlHint };
                }

                return new ApplicationDescription(uaAppDesc.ApplicationUri, uaAppDesc.ProductUri, uaAppDesc.ApplicationName,
                    uaAppDesc.Type, uaAppDesc.GatewayServerUri, uaAppDesc.DiscoveryProfileUri, discoveryUrls);
            }

            public override IList<EndpointDescription> GetEndpointDescriptions(string endpointUrlHint)
            {
                var certStr = ApplicationCertificate.Export(X509ContentType.Cert);
                ApplicationDescription localAppDesc = CreateApplicationDescriptionFromEndpointHint(endpointUrlHint);

                var epNoSecurity = new EndpointDescription(
                    endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.None, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None],
                    new UserTokenPolicy[]
                    {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                    }, Types.TransportProfileBinary, 0);

                var epSignBasic128Rsa15 = new EndpointDescription(
                    endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.Sign, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic128Rsa15],
                    new UserTokenPolicy[]
                    {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                    }, Types.TransportProfileBinary, 0);

                var epSignBasic256 = new EndpointDescription(
                    endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.Sign, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256],
                    new UserTokenPolicy[]
                    {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                    }, Types.TransportProfileBinary, 0);

                var epSignBasic256Sha256 = new EndpointDescription(
                    endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.Sign, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256],
                    new UserTokenPolicy[]
                    {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                    }, Types.TransportProfileBinary, 0);

                var epSignRsa128Sha256 = new EndpointDescription(
                    endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.Sign, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes128_Sha256_RsaOaep],
                    new UserTokenPolicy[]
                    {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes128_Sha256_RsaOaep]),
                    }, Types.TransportProfileBinary, 0);

                var epSignRsa256Sha256 = new EndpointDescription(
                    endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.Sign, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes256_Sha256_RsaPss],
                    new UserTokenPolicy[]
                    {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes256_Sha256_RsaPss]),
                    }, Types.TransportProfileBinary, 0);

                var epSignEncryptBasic128Rsa15 = new EndpointDescription(
                    endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.SignAndEncrypt, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic128Rsa15],
                    new UserTokenPolicy[]
                    {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                    }, Types.TransportProfileBinary, 0);

                var epSignEncryptBasic256 = new EndpointDescription(
                    endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.SignAndEncrypt, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256],
                    new UserTokenPolicy[]
                    {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                    }, Types.TransportProfileBinary, 0);

                var epSignEncryptBasic256Sha256 = new EndpointDescription(
                    endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.SignAndEncrypt, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256],
                    new UserTokenPolicy[]
                    {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                    }, Types.TransportProfileBinary, 0);

                var epSignEncryptRsa128Sha256 = new EndpointDescription(
                    endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.SignAndEncrypt, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes128_Sha256_RsaOaep],
                    new UserTokenPolicy[]
                    {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes128_Sha256_RsaOaep]),
                    }, Types.TransportProfileBinary, 0);

                var epSignEncryptRsa256Sha256 = new EndpointDescription(
                    endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.SignAndEncrypt, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes256_Sha256_RsaPss],
                    new UserTokenPolicy[]
                    {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                        new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes256_Sha256_RsaPss]),
                    }, Types.TransportProfileBinary, 0);

                return new EndpointDescription[]
                {
                    epNoSecurity,
                    epSignRsa256Sha256, epSignEncryptRsa256Sha256,
                    epSignRsa128Sha256, epSignEncryptRsa128Sha256,
                    epSignBasic256Sha256, epSignEncryptBasic256Sha256,
                    epSignBasic256, epSignEncryptBasic256,
                    epSignBasic128Rsa15, epSignEncryptBasic128Rsa15
                };
            }

            public override ApplicationDescription GetApplicationDescription(string endpointUrlHint)
            {
                return CreateApplicationDescriptionFromEndpointHint(endpointUrlHint);
            }

            protected override DataValue HandleReadRequestInternal(NodeId id)
            {
                if (id.NamespaceIndex == 2 &&
                    AddressSpaceTable.TryGetValue(id, out Node node))
                {
                    if (node == Node1D)
                    {
                        return new DataValue(new float[] { 1.0f, 2.0f, 3.0f }, StatusCode.Good, DateTime.Now);
                    }
                    else if (node == Node2D)
                    {
                        return new DataValue(new float[2, 2]
                        {
                            { 1.0f, 2.0f },
                            { 3.0f, 4.0f }
                        }, StatusCode.Good, DateTime.Now);
                    }
                    else
                    {
                        return new DataValue(3.14159265, StatusCode.Good, DateTime.Now);
                    }
                }

                return base.HandleReadRequestInternal(id);
            }

            private List<DataValue> testHistoryPoints = null;

            public override UInt32 HandleHistoryReadRequest(object session, object readDetails, HistoryReadValueId id,
                ContinuationPointHistory continuationPoint, List<DataValue> results, ref int? offsetContinueFit)
            {
                if (testHistoryPoints == null)
                {
                    testHistoryPoints = new List<DataValue>();

                    var dt = new DateTime(2015, 12, 1);
                    for (int i = 0; i < 100000; i++)
                    {
                        testHistoryPoints.Add(new DataValue(
                            Math.Sin(i * 0.3) + Math.Cos(i * 0.17) * 0.5 + Math.Sin(i * 0.087) * 0.25, StatusCode.Good,
                            dt));
                        dt = dt.AddHours(1);
                    }
                }

                int startOffset = continuationPoint.IsValid ? continuationPoint.Offset : 0;
                if (readDetails is ReadRawModifiedDetails)
                {
                    var rd = readDetails as ReadRawModifiedDetails;
                    for (int i = 0; i < 100000; i++)
                    {
                        var p = testHistoryPoints[i];
                        if (p.SourceTimestamp >= rd.StartTime &&
                            p.SourceTimestamp < rd.EndTime)
                        {
                            // Skip startOffset points
                            if (startOffset > 0)
                            {
                                startOffset--;
                                continue;
                            }

                            results.Add(p);
                        }
                    }

                    return (UInt32)StatusCode.Good;
                }

                return (UInt32)StatusCode.BadHistoryOperationUnsupported;
            }

            public override UInt32 HandleHistoryEventReadRequest(object session, object readDetails,
                HistoryReadValueId id, ContinuationPointHistory continuationPoint, List<object[]> results)
            {
                if (readDetails is ReadEventDetails)
                {
                    var rd = readDetails as ReadEventDetails;

                    var dt = rd.StartTime;
                    for (int i = 0; i < 5; i++)
                    {
                        var ev = GenerateSampleAlarmEvent(dt);
                        results.Add(NetDispatcher.MatchFilterClauses(rd.SelectClauses, ev));
                        dt = dt.AddMinutes(1);
                    }

                    return (UInt32)StatusCode.Good;
                }

                return (UInt32)StatusCode.BadHistoryOperationUnsupported;
            }

            protected int rowCount = 1;
            protected Random rnd = new Random();

            // These numbers are allowed to wrap in case of overflow
            // These are usually used by the client to match events
            protected UInt64 nextEventId = 1;

            private EventNotification GenerateSampleAlarmEvent(DateTime eventTime)
            {
                return new EventNotification(new EventNotification.Field[]
                {
					// During publishing, operand BrowsePaths are matched
					// against UA select clauses from the subscriber.
					// The operands shown here are the most common requested (90% of cases).
					// Types match operand BrowsePath, do not change them and remember
					// casting when passing into a variant.

					new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("EventId")}
                        ),
                        Value = nextEventId
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("EventType")}
                        ),
                        Value = new NodeId(UAConst.ExclusiveLevelAlarmType)
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("SourceName")}
                        ),
                        Value = "Source name"
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("Time")}
                        ),
                        Value = eventTime,
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("Message")}
                        ),
                        Value = new LocalizedText("Event message")
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("Severity")}
                        ),
						// Severity is 0 to 1000
						Value = (UInt16) (rnd.Next() % 1000)
                    },
					// ActiveState object is a name, Id gives the value specified by the name
					// The names do not mean anything (just display text), but Id is important
					new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("ActiveState")}
                        ),
                        Value = new LocalizedText("Active")
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
							// Represents ActiveState.Id
							new[] {new QualifiedName("ActiveState"), new QualifiedName("Id")}
                        ),
						// Inactive specifies false, Active specifies true
						Value = true
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("ActiveState"), new QualifiedName("EffectiveDisplayName")}
                        ),
                        Value = new LocalizedText("Alarm active")
                    },
					// Same rules for AckedState
					new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("AckedState")}
                        ),
                        Value = new LocalizedText("Acknowledged")
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
							// Represents AckedState.Id
							new[] {new QualifiedName("AckedState"), new QualifiedName("Id")}
                        ),
						// Inactive specifies false, Active specifies true
						Value = true,
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("Retain")}
                        ),
                        Value = true
                    },
                    new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            new[] {new QualifiedName("ConditionName")}
                        ),
                        Value = "Sample alarm"
                    },
					// Necessary field for alarms
					new EventNotification.Field()
                    {
                        Operand = new SimpleAttributeOperand(
                            NodeId.Zero, new[] {new QualifiedName("ConditionType")},
                            NodeAttribute.NodeId, null
                        ),
                        Value = NodeId.Zero
                    },
                });
            }

            public void PlayRow()
            {
                //Console.WriteLine("Play row {0}", rowCount);

                foreach (var node in TrendNodes)
                {
                    var dv = new DataValue((float)(rowCount + 0.1 * rnd.NextDouble()), StatusCode.Good, DateTime.Now);
                    MonitorNotifyDataChange(node.Id, dv);
                }

                ++rowCount;

                var eventTime = DateTime.UtcNow;
                var ev = GenerateSampleAlarmEvent(eventTime);
                // MonitorNotifyEvent(new NodeId(UAConst.Server), ev);

                nextEventId++;
            }

            private void LoadCertificateAndPrivateKey()
            {
                try
                {
                    // Try to load existing (public key) and associated private key
                    appCertificate = new X509Certificate2("ServerCert.der");
                    cryptPrivateKey = RSA.Create();
                    cryptPrivateKey.KeySize = 2048;

                    var rsaPrivParams = UASecurity.ImportRSAPrivateKey(File.ReadAllText("ServerKey.pem"));
                    cryptPrivateKey.ImportParameters(rsaPrivParams);
                }
                catch
                {
                    // Make a new certificate (public key) and associated private key
                    var dn = new X500DistinguishedName("CN=Server certificate;OU=Demo organization",
                        X500DistinguishedNameFlags.UseSemicolons);
                    SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
                    sanBuilder.AddUri(new Uri("urn:DemoApplication"));

                    using (RSA rsa = RSA.Create(4096))
                    {
                        var request = new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                        request.CertificateExtensions.Add(sanBuilder.Build());
                        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
                        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

                        request.CertificateExtensions.Add(new X509KeyUsageExtension(
                            X509KeyUsageFlags.DigitalSignature |
                            X509KeyUsageFlags.NonRepudiation |
                            X509KeyUsageFlags.DataEncipherment |
                            X509KeyUsageFlags.KeyEncipherment, false));

                        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection {
                            new Oid("1.3.6.1.5.5.7.3.8"),
                            new Oid("1.3.6.1.5.5.7.3.1"),
                            new Oid("1.3.6.1.5.5.7.3.2"),
                            new Oid("1.3.6.1.5.5.7.3.3"),
                            new Oid("1.3.6.1.5.5.7.3.4"),
                            new Oid("1.3.6.1.5.5.7.3.8"),
                            new Oid("1.3.6.1.5.5.7.3.9"),
                        }, true));

                        var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)),
                            new DateTimeOffset(DateTime.UtcNow.AddDays(3650)));

                        appCertificate = new X509Certificate2(certificate.Export(X509ContentType.Pfx, ""),
                            "", X509KeyStorageFlags.DefaultKeySet);

                        var certPrivateParams = rsa.ExportParameters(true);
                        File.WriteAllText("ServerCert.der", UASecurity.ExportPEM(appCertificate));
                        File.WriteAllText("ServerKey.pem", UASecurity.ExportRSAPrivateKey(certPrivateParams));

                        cryptPrivateKey = RSA.Create();
                        cryptPrivateKey.KeySize = 2048;
                        cryptPrivateKey.ImportParameters(certPrivateParams);
                    }
                }
            }
        }

        private static void Main(string[] args)
        {
            //TestSerialization();
            TestServer();
        }

        private static void TestServer()
        {
            var sw = new Stopwatch();
            sw.Start();

            var app = new DemoApplication();
            using ILoggerFactory factory = LoggerFactory.Create(builder => builder.AddConsole());
            var logger = factory.CreateLogger(nameof(TestServer));
            var server = new LibUA.Server.Master(app, 7718, 10, 30, 100, logger);
            server.Start();

            sw.Stop();
            logger.Log(LogLevel.Information, "Created and started server in {0} ms", sw.ElapsedMilliseconds.ToString("N3"));
            logger.Log(LogLevel.Information, "opc.tcp://localhost:7718");

            var timer = new Timer(1000);
            timer.Elapsed += (sender, e) => { app.PlayRow(); };

            timer.Start();
            Console.ReadKey();
            timer.Stop();

            server.Stop();
        }
    }
}