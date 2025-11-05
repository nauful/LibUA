using LibUA.Core;

namespace LibUA.Tests
{
    public class ClientTests : IDisposable
    {
        private readonly TestServerFixture serverFixture;

        public ClientTests()
        {
            serverFixture = new TestServerFixture();
        }

        public void Dispose()
        {
            serverFixture?.Dispose();
            GC.SuppressFinalize(this);
        }

        #region Connection and Secure Channel Management

        [Fact]
        public void TestConnect()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                var result = client.Connect();
                Assert.Equal(StatusCode.Good, result);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestDisconnect()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                var result = client.Disconnect();
                Assert.Equal(StatusCode.Good, result);
            }
            finally
            {
                client?.Dispose();
            }
        }

        [Fact]
        public void TestOpenSecureChannel()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                var result = client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);
                Assert.Equal(StatusCode.Good, result);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestCloseSecureChannel()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);
                var result = client.CloseSecureChannel();
                Assert.Equal(StatusCode.Good, result);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        #endregion

        #region Session Management

        [Fact]
        public void TestCreateSession()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                var result = client.CreateSession(appDesc, "urn:DemoApplication", 120);
                Assert.Equal(StatusCode.Good, result);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestActivateSession_Anonymous()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);

                var result = client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);
                Assert.Equal(StatusCode.Good, result);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestActivateSession_Username()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);

                // Setup to ONLY succeed if the credentials match.
                var username = "plc-user";
                var password = "123"u8.ToArray();
                serverFixture.SessionValidateClientUserHandler = (_, userToken) =>
                    userToken is UserIdentityUsernameToken userNameToken
                    && userNameToken.Username == username
                    && userNameToken.PasswordHash.SequenceEqual(password);

                var result = client.ActivateSession(
                    new UserIdentityUsernameToken("1", username, password, Types.SignatureAlgorithmRsaOaep),
                    ["en"]);
                Assert.Equal(StatusCode.Good, result);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestActivateSession_Certificate_OnInsecure()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                
                // Setup to ONLY succeed if the certificate matches.
                serverFixture.SessionValidateClientUserHandler = (_, userToken) =>
                    userToken is UserIdentityX509IdentityToken x509Token
                    // ReSharper disable once AccessToDisposedClosure
                    && x509Token.CertificateData.SequenceEqual(client.ClientCertificate)
                    && x509Token.PrivateKey == null;

                var result = client.ActivateSession(
                    new UserIdentityX509IdentityToken("2", client.ClientCertificate, client.ApplicationPrivateKey),
                    ["en"]);
                Assert.Equal(StatusCode.Good, result);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestActivateSession_Certificate_OnSecure()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            var localeIDs = new[] { "en" };
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);
                client.FindServers(out ApplicationDescription[] _, localeIDs);
                client.GetEndpoints(out EndpointDescription[] endpointDescs, localeIDs);
                client.Disconnect();

                // Will fail if no matching message security mode and security policy is found
                var messageSecurityMode = MessageSecurityMode.SignAndEncrypt;
                var securityPolicy = SecurityPolicy.Basic256Sha256;
                var endpointDesc = endpointDescs.First(e =>
                    e.SecurityMode == messageSecurityMode &&
                    e.SecurityPolicyUri == Types.SLSecurityPolicyUris[(int)securityPolicy]);
                byte[] serverCert = endpointDesc.ServerCertificate;
                string policyId = endpointDesc.UserIdentityTokens.First(e => e.TokenType == UserTokenType.Certificate).PolicyId;

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                // Setup to ONLY succeed if the certificate matches.
                serverFixture.SessionValidateClientUserHandler = (_, userToken) =>
                    userToken is UserIdentityX509IdentityToken x509Token
                    // ReSharper disable once AccessToDisposedClosure
                    && x509Token.CertificateData.SequenceEqual(client.ClientCertificate)
                    && x509Token.PrivateKey == null;

                client.Connect();
                client.OpenSecureChannel(messageSecurityMode, securityPolicy, serverCert);
                client.CreateSession(appDesc, "urn:DemoApplication", 120);

                var result = client.ActivateSession(
                    new UserIdentityX509IdentityToken(policyId, client.ClientCertificate, client.ApplicationPrivateKey),
                    localeIDs);
                Assert.Equal(StatusCode.Good, result);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestCloseSession()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                var result = client.CloseSession();
                Assert.Equal(StatusCode.Good, result);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        #endregion

        #region Data Access Operations

        [Fact]
        public void TestRead()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                var readValues = new ReadValueId[]
                {
                    new(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName(0, null)),
                    new(new NodeId(2, 2), NodeAttribute.Value, null, new QualifiedName(0, null)),
                    new(new NodeId(2, 3), NodeAttribute.Value, null, new QualifiedName(0, null)),
                };

                var result = client.Read(readValues, out DataValue[] dvs);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(dvs);
                Assert.Equal(3, dvs.Length);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestWrite()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                var writeValues = new WriteValue[]
                {
                    new(
                        new NodeId(2, 0), NodeAttribute.Value,
                        null, new DataValue(3.14159265, StatusCode.Good, DateTime.Now))
                };

                var result = client.Write(writeValues, out uint[] respStatuses);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(respStatuses);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestBrowse()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                var browseDescs = new BrowseDescription[]
                {
                    new(
                        new NodeId(2, 0),
                        BrowseDirection.Both,
                        NodeId.Zero,
                        true, 0xFFFFFFFFu, BrowseResultMask.All)
                };

                var result = client.Browse(browseDescs, 10000, out BrowseResult[] browseResults);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(browseResults);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestBrowseNext()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                // First browse to get a continuation point
                var browseDescs = new BrowseDescription[]
                {
                    new(
                        new NodeId(2, 0),
                        BrowseDirection.Both,
                        NodeId.Zero,
                        true, 0xFFFFFFFFu, BrowseResultMask.All)
                };

                client.Browse(browseDescs, 10000, out BrowseResult[] browseResults);

                // Then test BrowseNext with continuation point
                if (browseResults.Length > 0 && browseResults[0].ContinuationPoint != null)
                {
                    var result = client.BrowseNext(new[] { browseResults[0].ContinuationPoint }, false, out BrowseResult[] nextResults);
                    Assert.Equal(StatusCode.Good, result);
                    Assert.NotNull(nextResults);
                }
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestTranslateBrowsePathsToNodeIds()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                var browsePaths = new BrowsePath[]
                {
                    new(
                        NodeId.Zero,
                        [
                            new(
                                new NodeId(UAConst.Organizes),
                                false,
                                true,
                                new QualifiedName(0, null))
                        ])
                };

                var result = client.TranslateBrowsePathsToNodeIds(browsePaths, out BrowsePathResult[] results);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(results);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        #endregion

        #region Historical Data Access

        [Fact]
        public void TestHistoryRead()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                var historyReadDetails = new ReadRawModifiedDetails(false,
                    new DateTime(2015, 12, 1),
                    new DateTime(2015, 12, 2),
                    100, true);

                var result = client.HistoryRead(historyReadDetails, TimestampsToReturn.Both, false,
                    [
                        new(new NodeId(2, 1), null, new QualifiedName(), null),
                        new(new NodeId(2, 2), null, new QualifiedName(), null),
                        new(new NodeId(2, 3), null, new QualifiedName(), null),
                    ], out HistoryReadResult[] histResults);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(histResults);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestHistoryUpdate()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                var result = client.HistoryUpdate(
                    [
                        new(new NodeId(2, 1), PerformUpdateType.Replace,
                        [
                            new(3.14159265, StatusCode.Good, DateTime.Now),
                        ])
                    ], out uint[] respStatuses);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(respStatuses);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        #endregion

        #region Subscription and Monitoring

        [Fact]
        public void TestCreateSubscription()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                var result = client.CreateSubscription(0, 1000, true, 0, out uint subscrId);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotEqual(0u, subscrId);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestModifySubscription()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                // Create a subscription first
                client.CreateSubscription(0, 1000, true, 0, out uint subscrId);

                var result = client.ModifySubscription(subscrId, 0, 100, true, 0, out uint respStatus);
                Assert.Equal(StatusCode.Good, result);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestDeleteSubscription()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                // Create a subscription first
                client.CreateSubscription(0, 1000, true, 0, out uint subscrId);

                var result = client.DeleteSubscription([subscrId], out uint[] respStatuses);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(respStatuses);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestSetPublishingMode()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                // Create a subscription first
                client.CreateSubscription(0, 1000, true, 0, out uint subscrId);

                var result = client.SetPublishingMode(true, [subscrId], out uint[] respStatuses);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(respStatuses);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestCreateMonitoredItems()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                // Create a subscription first
                client.CreateSubscription(0, 1000, true, 0, out uint subscrId);

                var result = client.CreateMonitoredItems(subscrId, TimestampsToReturn.Both,
                    [
                        new(
                            new ReadValueId(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName()),
                            MonitoringMode.Reporting,
                            new MonitoringParameters(1u, 0, null, 100, false))
                    ], out MonitoredItemCreateResult[] monitorCreateResults);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(monitorCreateResults);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestModifyMonitoredItems()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                // Create a subscription first
                client.CreateSubscription(0, 1000, true, 0, out uint subscrId);

                // Create monitored items first
                client.CreateMonitoredItems(subscrId, TimestampsToReturn.Both,
                    [
                        new(
                            new ReadValueId(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName()),
                            MonitoringMode.Reporting,
                            new MonitoringParameters(1u, 0, null, 100, false))
                    ], out _);

                var result = client.ModifyMonitoredItems(subscrId, TimestampsToReturn.Both,
                    [
                        new(
                            1u,
                            new MonitoringParameters(1u, 0, null, 200, false))
                    ], out MonitoredItemModifyResult[] modifyResults);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(modifyResults);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestDeleteMonitoredItems()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                var appDesc = new ApplicationDescription(
                    "urn:DemoApplication", "http://quantensystems.com/",
                    new LocalizedText("en-US", "QuantenSystems demo server"), ApplicationType.Client,
                    null, null, null);

                client.CreateSession(appDesc, "urn:DemoApplication", 120);
                client.ActivateSession(new UserIdentityAnonymousToken("0"), ["en"]);

                // Create a subscription first
                client.CreateSubscription(0, 1000, true, 0, out uint subscrId);

                // Create monitored items first
                client.CreateMonitoredItems(subscrId, TimestampsToReturn.Both,
                    [
                        new(
                            new ReadValueId(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName()),
                            MonitoringMode.Reporting,
                            new MonitoringParameters(1u, 0, null, 100, false))
                    ], out _);

                var result = client.DeleteMonitoredItems(subscrId, [1u], out uint[] respStatuses);
                Assert.Equal(StatusCode.Good, result);
                Assert.NotNull(respStatuses);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        #endregion

        #region Server Validation Tests

        [Fact]
        public void TestServerClient_ValidateApplicationDescriptions()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                Assert.Equal(StatusCode.Good, client.FindServers(out ApplicationDescription[] appDescs, null));
                Assert.NotEmpty(appDescs);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        [Fact]
        public void TestServerClient_ValidateUnfilteredEndpointDescriptions()
        {
            var client = new TestClient(TestServerFixture.HostName, TestServerFixture.PortNumber, 100);
            try
            {
                client.Connect();
                client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);

                Assert.Equal(StatusCode.Good, client.GetEndpoints(out EndpointDescription[] endpointDescs, null));
                Assert.NotEmpty(endpointDescs);
            }
            finally
            {
                client?.Disconnect();
                client?.Dispose();
            }
        }

        #endregion

        #region Error Handling and Edge Cases

        [Fact]
        public void TestConnectionFailure()
        {
            // Try to connect to a non-existent server
            var badClient = new TestClient("127.0.0.1", 9999, 100);
            try
            {
                var result = badClient.Connect();
                Assert.NotEqual(StatusCode.Good, result);
            }
            finally
            {
                badClient?.Dispose();
            }
        }

        #endregion
    }
}
