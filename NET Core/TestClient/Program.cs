using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using LibUA;
using LibUA.Core;

namespace TestClient
{
    internal class Program
    {
        private class DemoClient : Client
        {
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

            private void LoadCertificateAndPrivateKey()
            {
                try
                {
                    // Try to load existing (public key) and associated private key
                    appCertificate = new X509Certificate2("ClientCert.der");
                    cryptPrivateKey = RSA.Create();
                    cryptPrivateKey.KeySize = 2048;

                    var rsaPrivParams = UASecurity.ImportRSAPrivateKey(File.ReadAllText("ClientKey.pem"));
                    cryptPrivateKey.ImportParameters(rsaPrivParams);
                }
                catch
                {
                    // Make a new certificate (public key) and associated private key
                    var dn = new X500DistinguishedName("CN=Client certificate;OU=Demo organization",
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
                        File.WriteAllText("ClientCert.der", UASecurity.ExportPEM(appCertificate));
                        File.WriteAllText("ClientKey.pem", UASecurity.ExportRSAPrivateKey(certPrivateParams));

                        cryptPrivateKey = RSA.Create();
                        cryptPrivateKey.KeySize = 2048;
                        cryptPrivateKey.ImportParameters(certPrivateParams);
                    }
                }
            }

            public DemoClient(string Target, int Port, int Timeout)
                : base(Target, Port, Timeout)
            {
                LoadCertificateAndPrivateKey();
            }

            public override void NotifyDataChangeNotifications(uint subscrId, uint[] clientHandles, DataValue[] notifications)
            {
                for (int i = 0; i < clientHandles.Length; i++)
                {
                    Console.WriteLine("subscrId {0} handle {1}: {2}", subscrId, clientHandles[i], notifications[i].Value.ToString());
                }
            }

            public override void NotifyEventNotifications(uint subscrId, uint[] clientHandles, object[][] notifications)
            {
                for (int i = 0; i < clientHandles.Length; i++)
                {
                    Console.WriteLine("subscrId {0} handle {1}: {2}", subscrId, clientHandles[i], string.Join(",", notifications[i]));
                }
            }
        }

        private static void Main(string[] args)
        {
            var appDesc = new ApplicationDescription(
                "urn:DemoApplication", "uri:DemoApplication", new LocalizedText("UA SDK client"),
                ApplicationType.Client, null, null, null);

            var client = new DemoClient("127.0.0.1", 7718, 1000);
            var messageSecurityMode = MessageSecurityMode.SignAndEncrypt;
            var securityPolicy = SecurityPolicy.Basic256Sha256;
            bool useAnonymousUser = true;

            client.Connect();
            client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);
            client.FindServers(out ApplicationDescription[] appDescs, new[] { "en" });
            client.GetEndpoints(out EndpointDescription[] endpointDescs, new[] { "en" });
            client.Disconnect();

            // Will fail if no matching message security mode and security policy is found
            var endpointDesc = endpointDescs.First(e =>
                e.SecurityMode == messageSecurityMode &&
                e.SecurityPolicyUri == Types.SLSecurityPolicyUris[(int)securityPolicy]);
            byte[] serverCert = endpointDesc.ServerCertificate;

            var connectRes = client.Connect();
            var openRes = client.OpenSecureChannel(messageSecurityMode, securityPolicy, serverCert);
            var createRes = client.CreateSession(appDesc, "urn:DemoApplication", 120);

            StatusCode activateRes;
            if (useAnonymousUser)
            {
                // Will fail if this endpoint does not allow Anonymous user tokens
                string policyId = endpointDesc.UserIdentityTokens.First(e => e.TokenType == UserTokenType.Anonymous).PolicyId;
                activateRes = client.ActivateSession(new UserIdentityAnonymousToken(policyId), new[] { "en" });
            }
            else
            {
                // Will fail if this endpoint does not allow UserName user tokens
                string policyId = endpointDesc.UserIdentityTokens.First(e => e.TokenType == UserTokenType.UserName).PolicyId;
                activateRes = client.ActivateSession(
                    new UserIdentityUsernameToken(policyId, "plc-user",
                        (new UTF8Encoding()).GetBytes("123"), Types.SignatureAlgorithmRsaOaep),
                    new[] { "en" });
            }

            var readRes = client.Read(new ReadValueId[]
                {
                    new ReadValueId(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName(0, null)),
                    new ReadValueId(new NodeId(2, 2), NodeAttribute.Value, null, new QualifiedName(0, null)),
                    new ReadValueId(new NodeId(2, 3), NodeAttribute.Value, null, new QualifiedName(0, null)),
                }, out DataValue[] dvs);

            //client.Browse(new BrowseDescription[]
            //{
            //		new BrowseDescription(
            //			new NodeId(2, 0),
            //			BrowseDirection.Both,
            //			NodeId.Zero,
            //			true, 0xFFFFFFFFu, BrowseResultMask.All)
            //}, 20, out browseResults);

            //while (browseResults[0].ContinuationPoint != null)
            //{
            //	client.BrowseNext(new[] { browseResults[0].ContinuationPoint }, false, out browseResults);
            //}

            client.Browse(new BrowseDescription[]
            {
                    new BrowseDescription(
                        new NodeId(2, 0),
                        BrowseDirection.Both,
                        NodeId.Zero,
                        true, 0xFFFFFFFFu, BrowseResultMask.All)
            }, 10000, out BrowseResult[] browseResults);

            //Queue<NodeId> nodeQueue = new Queue<NodeId>();
            //nodeQueue.Enqueue(new NodeId(0, (uint)UAConst.ObjectsFolder));
            //while (nodeQueue.TryDequeue(out NodeId currentNode))
            //{
            //	client.Browse(new BrowseDescription[]
            //	{
            //		new BrowseDescription(
            //			currentNode,
            //			BrowseDirection.Forward,
            //			NodeId.Zero,
            //			true, 0xFFFFFFFFu, BrowseResultMask.All)
            //	}, 10000, out BrowseResult[] childrenBrowseResults);
            //	foreach (var reference in childrenBrowseResults[0].Refs)
            //	{
            //		if (reference.ReferenceTypeId.EqualsNumeric(0, (uint)RefType.Organizes))
            //		{
            //			nodeQueue.Enqueue(reference.TargetId);
            //		}
            //	}
            //}

            client.Write(new WriteValue[]
                {
                    new WriteValue(
                        new NodeId(2, 0), NodeAttribute.Value,
                        null, new DataValue(3.14159265, StatusCode.GoodClamped, DateTime.Now))
                }, out uint[] respStatuses);

            client.HistoryRead(new ReadRawModifiedDetails(false,
                new DateTime(2015, 12, 1),
                new DateTime(2015, 12, 2),
                100, true), TimestampsToReturn.Both, false,
                new HistoryReadValueId[]
                {
                    new HistoryReadValueId(new NodeId(2, 1), null, new QualifiedName(), null),
                    new HistoryReadValueId(new NodeId(2, 2), null, new QualifiedName(), null),
                    new HistoryReadValueId(new NodeId(2, 3), null, new QualifiedName(), null),
                }, out HistoryReadResult[] histResults);

            client.HistoryUpdate(new HistoryUpdateData[]
                {
                    new HistoryUpdateData(new NodeId(2, 1), PerformUpdateType.Replace,
                    new DataValue[]
                    {
                        new DataValue(3.14159265, StatusCode.Good, DateTime.Now),
                    })
                }, out respStatuses);

            var eventFilterOperands = new SimpleAttributeOperand[]
                {
                    new SimpleAttributeOperand(
                        new[] { new QualifiedName("EventId") }
                    ),
                    new SimpleAttributeOperand(
                        new[] { new QualifiedName("EventType") }
                    ),
                    new SimpleAttributeOperand(
                        new[] { new QualifiedName("SourceName") }
                    ),
                    new SimpleAttributeOperand(
                        new[] { new QualifiedName("Time") }
                    ),
                    new SimpleAttributeOperand(
                        new[] { new QualifiedName("Message") }
                    ),
                    new SimpleAttributeOperand(
                        new[] { new QualifiedName("Severity") }
                    ),
                    new SimpleAttributeOperand(
                        new[] { new QualifiedName("ActiveState") }
                    ),
                    new SimpleAttributeOperand(
                        new[] { new QualifiedName("AckedState") }
                    ),
                    new SimpleAttributeOperand(
                        new[] { new QualifiedName("ConditionName") }
                    ),
                    new SimpleAttributeOperand(
                        new[] { new QualifiedName("ConditionType") }
                    ),
                };

            client.HistoryRead(new ReadEventDetails(
                new DateTime(2015, 12, 1),
                new DateTime(2015, 12, 2),
                100, eventFilterOperands), TimestampsToReturn.Both, false,
                new HistoryReadValueId[]
                {
                    new HistoryReadValueId(new NodeId(0, 2253), null, new QualifiedName(), null),
                }, out histResults);

            client.CreateSubscription(0, 1000, true, 0, out uint subscrId);

            // Second will have response BadSubscriptionIdInvalid
            client.SetPublishingMode(true, new[] { subscrId, 10u }, out respStatuses);

            client.ModifySubscription(subscrId, 0, 100, true, 0, out uint respStatus);

            uint clientHandleEventMonitor = 0;
            var tagsMonitorId = new uint[3];
            for (int i = 0; i < 3; i++) { tagsMonitorId[i] = (uint)(1 + i); }

            client.CreateMonitoredItems(subscrId, TimestampsToReturn.Both,
                new MonitoredItemCreateRequest[]
                {
                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(0, 2253), NodeAttribute.EventNotifier, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(clientHandleEventMonitor, 0, new EventFilter(eventFilterOperands, null), 100, true)),

                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(tagsMonitorId[0], 0, null, 100, false)),

                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 2), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(tagsMonitorId[1], 0, null, 100, false)),

                    new MonitoredItemCreateRequest(
                        new ReadValueId(new NodeId(2, 3), NodeAttribute.Value, null, new QualifiedName()),
                        MonitoringMode.Reporting,
                        new MonitoringParameters(tagsMonitorId[2], 0, null, 100, false))
                }, out MonitoredItemCreateResult[] monitorCreateResults);

            Console.ReadKey();

            // Last two should have BadMonitoredItemIdInvalid resp status
            client.DeleteMonitoredItems(subscrId, new uint[] { 0, 1, 2, 3, 4, 5 }, out respStatuses);
            client.DeleteSubscription(new[] { subscrId }, out respStatuses);

            client.Dispose();
        }
    }
}
