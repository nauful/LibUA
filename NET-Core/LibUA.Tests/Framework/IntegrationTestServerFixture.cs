using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
// Timer is accessed via System.Timers.Timer to avoid ambiguity with System.Threading.Timer
using LibUA.Core;
using LibUA.Server;
using Microsoft.Extensions.Logging.Abstractions;

namespace LibUA.Tests
{
    // Collection definition for integration tests — serializes all tests using this fixture
    [CollectionDefinition(nameof(IntegrationTestServerFixture))]
    public class IntegrationTestCollection : ICollectionFixture<IntegrationTestServerFixture>
    {
        // This class is never instantiated; it only carries the CollectionDefinition attribute.
    }

    public class IntegrationTestServerFixture : LibUA.Server.Application, IDisposable
    {
        public const string HostName = "localhost";
        public const int PortNumber = 7719;

        private readonly ApplicationDescription uaAppDesc;
        private readonly NodeObject ItemsRoot;
        private readonly NodeVariable[] TrendNodes;
        private readonly NodeVariable Node1D, Node2D;
        private X509Certificate2? appCertificate = null;
        private RSA? cryptPrivateKey = null;
        private readonly Server.Master server;
        // Lock object used to protect the PlayRow() call from the timer callback.
        // MonitorNotifyDataChange uses monitorMapRW (ReaderWriterLockSlim) which is safe
        // for concurrent reads, but the foreach over TrendNodes + multiple MonitorNotifyDataChange
        // calls should not overlap with test code that may be modifying the address space.
        private readonly object playRowLock = new();
        private readonly System.Timers.Timer playRowTimer;

        public Func<object, object, bool>? SessionValidateClientUserHandler { get; set; }

        public override X509Certificate2? ApplicationCertificate
        {
            get { return appCertificate; }
        }

        public override RSA? ApplicationPrivateKey
        {
            get { return cryptPrivateKey; }
        }

        public IntegrationTestServerFixture()
        {
            var logger = new NullLogger<IntegrationTestServerFixture>();
            server = new Server.Master(this, PortNumber, 10, 30, 100, logger);

            LoadCertificateAndPrivateKey();

            uaAppDesc = new ApplicationDescription(
                "urn:DemoApplication", "http://quantensystems.com/",
                new LocalizedText("en-US", "QuantenSystems integration test server"), ApplicationType.Server,
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

            // Start the server
            server.Start();

            // Start PlayRow timer at 500ms intervals to generate data change notifications.
            // The PlayRow() call is lock-protected because it iterates all 1000 TrendNodes
            // and calls MonitorNotifyDataChange for each — the monitorMap uses ReaderWriterLockSlim.
            playRowTimer = new System.Timers.Timer(500);
            playRowTimer.Elapsed += (sender, e) =>
            {
                lock (playRowLock)
                {
                    PlayRow();
                }
            };
            playRowTimer.Start();

            // Give the server a moment to stabilize before tests connect.
            // During this time, PlayRow fires ~6 times, establishing a data flow baseline.
            Thread.Sleep(3000);
        }

        public override object? SessionCreate(SessionCreationInfo sessionInfo)
        {
            return null;
        }

        public override bool SessionValidateClientApplication(object session,
            ApplicationDescription clientApplicationDescription, byte[] clientCertificate, string sessionName)
        {
            return true;
        }

        public override void SessionRelease(object session)
        {
        }

        public override bool SessionValidateClientUser(object session, object userIdentityToken)
        {
            if (SessionValidateClientUserHandler != null)
            {
                return SessionValidateClientUserHandler(session, userIdentityToken);
            }

            if (userIdentityToken is UserIdentityAnonymousToken)
            {
                return true;
            }
            else if (userIdentityToken is UserIdentityUsernameToken usernameToken)
            {
                _ = usernameToken.Username;
                _ = new UTF8Encoding().GetString(usernameToken.PasswordHash);
                return true;
            }
            else if (userIdentityToken is UserIdentityX509IdentityToken x509Token)
            {
                _ = x509Token.CertificateData;
                return true;
            }

            throw new Exception("Unhandled user identity token type");
        }

        private ApplicationDescription CreateApplicationDescriptionFromEndpointHint(string endpointUrlHint)
        {
            string[]? discoveryUrls = uaAppDesc.DiscoveryUrls;
            if (discoveryUrls == null && !string.IsNullOrEmpty(endpointUrlHint))
            {
                discoveryUrls = [endpointUrlHint];
            }

            return new ApplicationDescription(uaAppDesc.ApplicationUri, uaAppDesc.ProductUri, uaAppDesc.ApplicationName,
                uaAppDesc.Type, uaAppDesc.GatewayServerUri, uaAppDesc.DiscoveryProfileUri, discoveryUrls);
        }

        public override IList<EndpointDescription> GetEndpointDescriptions(string endpointUrlHint)
        {
            var certStr = ApplicationCertificate?.Export(X509ContentType.Cert);
            ApplicationDescription localAppDesc = CreateApplicationDescriptionFromEndpointHint(endpointUrlHint);

            var epNoSecurity = new EndpointDescription(
                endpointUrlHint, localAppDesc, certStr,
                MessageSecurityMode.None, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None],
                [
                    new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                    new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                ], Types.TransportProfileBinary, 0);

            var epSignEncryptBasic256Sha256 = new EndpointDescription(
                endpointUrlHint, localAppDesc, certStr,
                MessageSecurityMode.SignAndEncrypt, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256],
                [
                    new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                    new UserTokenPolicy("1", UserTokenType.UserName, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                    new UserTokenPolicy("2", UserTokenType.Certificate, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]),
                ], Types.TransportProfileBinary, 0);

            return
            [
                epNoSecurity,
                epSignEncryptBasic256Sha256,
            ];
        }

        public override ApplicationDescription GetApplicationDescription(string endpointUrlHint)
        {
            return CreateApplicationDescriptionFromEndpointHint(endpointUrlHint);
        }

        protected override DataValue HandleReadRequestInternal(NodeId id)
        {
            if (id.NamespaceIndex == 2 &&
                AddressSpaceTable.TryGetValue(id, out Node? node))
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

        private List<DataValue>? testHistoryPoints;

        public override UInt32 HandleHistoryReadRequest(object session, object readDetails, HistoryReadValueId id,
            ContinuationPointHistory continuationPoint, List<DataValue> results, ref int? offsetContinueFit)
        {
            if (testHistoryPoints == null)
            {
                testHistoryPoints = [];

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
            if (readDetails is ReadRawModifiedDetails rd)
            {
                for (int i = 0; i < 100000; i++)
                {
                    var p = testHistoryPoints[i];
                    if (p.SourceTimestamp >= rd.StartTime &&
                        p.SourceTimestamp < rd.EndTime)
                    {
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
            if (readDetails is ReadEventDetails rd)
            {
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
        protected Random rnd = new();
        protected UInt64 nextEventId = 1;

        public void PlayRow()
        {
            // Thread-safe: PlayRow is only called from the timer callback (single thread) or
            // from test setup (single-threaded). The lock protects against any future changes.
            foreach (var node in TrendNodes)
            {
                var dv = new DataValue((float)(rowCount + 0.1 * rnd.NextDouble()), StatusCode.Good, DateTime.Now);
                MonitorNotifyDataChange(node.Id, dv);
            }

            ++rowCount;

            var eventTime = DateTime.UtcNow;
            var ev = GenerateSampleAlarmEvent(eventTime);
            nextEventId++;
        }

        private EventNotification GenerateSampleAlarmEvent(DateTime eventTime)
        {
            return new EventNotification(
            [
                new()
                {
                    Operand = new SimpleAttributeOperand(
                        [new QualifiedName("EventId")]
                    ),
                    Value = nextEventId
                },
                new()
                {
                    Operand = new SimpleAttributeOperand(
                        [new QualifiedName("EventType")]
                    ),
                    Value = new NodeId(UAConst.ExclusiveLevelAlarmType)
                },
                new()
                {
                    Operand = new SimpleAttributeOperand(
                        [new QualifiedName("SourceName")]
                    ),
                    Value = "Source name"
                },
                new()
                {
                    Operand = new SimpleAttributeOperand(
                        [new QualifiedName("Time")]
                    ),
                    Value = eventTime,
                },
                new()
                {
                    Operand = new SimpleAttributeOperand(
                        [new QualifiedName("Message")]
                    ),
                    Value = new LocalizedText("Event message")
                },
                new()
                {
                    Operand = new SimpleAttributeOperand(
                        [new QualifiedName("Severity")]
                    ),
                    Value = (UInt16)(rnd.Next() % 1000)
                },
                new()
                {
                    Operand = new SimpleAttributeOperand(
                        [new QualifiedName("ActiveState")]
                    ),
                    Value = new LocalizedText("Active")
                },
                new()
                {
                    Operand = new SimpleAttributeOperand(
                        [new QualifiedName("ActiveState"), new QualifiedName("Id")]
                    ),
                    Value = true
                },
                new()
                {
                    Operand = new SimpleAttributeOperand(
                        [new QualifiedName("ActiveState"), new QualifiedName("EffectiveDisplayName")]
                    ),
                    Value = new LocalizedText("Alarm active")
                },
                new()
                {
                    Operand = new SimpleAttributeOperand(
                        [new QualifiedName("AckedState")]
                    ),
                    Value = new LocalizedText("Acknowledged")
                },
                new()
                {
                    Operand = new SimpleAttributeOperand(
                        [new QualifiedName("AckedState"), new QualifiedName("Id")]
                    ),
                    Value = true,
                },
                new()
                {
                    Operand = new SimpleAttributeOperand(
                        [new QualifiedName("Retain")]
                    ),
                    Value = true
                },
                new()
                {
                    Operand = new SimpleAttributeOperand(
                        [new QualifiedName("ConditionName")]
                    ),
                    Value = "Sample alarm"
                },
                new()
                {
                    Operand = new SimpleAttributeOperand(
                        NodeId.Zero, [new QualifiedName("ConditionType")],
                        NodeAttribute.NodeId, null
                    ),
                    Value = NodeId.Zero
                },
            ]);
        }

        private void LoadCertificateAndPrivateKey()
        {
            try
            {
                appCertificate = new X509Certificate2("ServerCert.pem");
                cryptPrivateKey = RSA.Create();
                cryptPrivateKey.KeySize = 2048;

                var rsaPrivParams = UASecurity.ImportRSAPrivateKey(File.ReadAllText("ServerKey.pem"));
                cryptPrivateKey.ImportParameters(rsaPrivParams);
            }
            catch
            {
                var dn = new X500DistinguishedName("CN=Server certificate;OU=Demo organization",
                    X500DistinguishedNameFlags.UseSemicolons);
                SubjectAlternativeNameBuilder sanBuilder = new();
                sanBuilder.AddUri(new Uri("urn:DemoApplication"));

                using RSA rsa = RSA.Create(4096);
                var request = new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(sanBuilder.Build());
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
                request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

                request.CertificateExtensions.Add(new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature |
                    X509KeyUsageFlags.NonRepudiation |
                    X509KeyUsageFlags.DataEncipherment |
                    X509KeyUsageFlags.KeyEncipherment, false));

                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                    [
                        new Oid("1.3.6.1.5.5.7.3.8"),
                        new Oid("1.3.6.1.5.5.7.3.1"),
                        new Oid("1.3.6.1.5.5.7.3.2"),
                        new Oid("1.3.6.1.5.5.7.3.3"),
                        new Oid("1.3.6.1.5.5.7.3.4"),
                        new Oid("1.3.6.1.5.5.7.3.8"),
                        new Oid("1.3.6.1.5.5.7.3.9"),
                    ], true));

                appCertificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)),
                    new DateTimeOffset(DateTime.UtcNow.AddDays(3650)));

                var certPrivateParams = rsa.ExportParameters(true);
                File.WriteAllText("ServerCert.pem", UASecurity.ExportPEM(appCertificate));
                File.WriteAllText("ServerKey.pem", UASecurity.ExportRSAPrivateKey(certPrivateParams));

                cryptPrivateKey = RSA.Create();
                cryptPrivateKey.KeySize = 2048;
                cryptPrivateKey.ImportParameters(certPrivateParams);
            }
        }

        public void Dispose()
        {
            playRowTimer?.Stop();
            playRowTimer?.Dispose();
            server.Stop();
            GC.SuppressFinalize(this);
        }
    }
}