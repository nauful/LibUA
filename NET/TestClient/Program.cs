using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using LibUA;
using LibUA.Core;
using LibUA.Security.Cryptography;
using LibUA.Security.Cryptography.X509Certificates;

namespace TestClient
{
	class Program
	{
		class DemoClient : Client
		{
			X509Certificate2 appCertificate = null;
			RSACryptoServiceProvider cryptPrivateKey = null;

			public override X509Certificate2 ApplicationCertificate
			{
				get { return appCertificate; }
			}

			public override RSACryptoServiceProvider ApplicationPrivateKey
			{
				get { return cryptPrivateKey; }
			}

			private void LoadCertificateAndPrivateKey()
			{
				try
				{
					// Try to load existing (public key) and associated private key
					appCertificate = new X509Certificate2("ClientCert.der");
					cryptPrivateKey = new RSACryptoServiceProvider();

					var rsaPrivParams = UASecurity.ImportRSAPrivateKey(File.ReadAllText("ClientKey.pem"));
					cryptPrivateKey.ImportParameters(rsaPrivParams);
				}
				catch
				{
					// Make a new certificate (public key) and associated private key
					var dn = new X500DistinguishedName("CN=Client certificate;OU=Demo organization", X500DistinguishedNameFlags.UseSemicolons);

					var keyCreationParameters = new CngKeyCreationParameters()
					{
						KeyUsage = CngKeyUsages.AllUsages,
						KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
						ExportPolicy = CngExportPolicies.AllowPlaintextExport
					};

					keyCreationParameters.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(1024), CngPropertyOptions.None));
					var cngKey = CngKey.Create(CngAlgorithm2.Rsa, "KeyName", keyCreationParameters);

					var certParams = new X509CertificateCreationParameters(dn)
					{
						StartTime = DateTime.Now,
						EndTime = DateTime.Now.AddYears(10),
						SignatureAlgorithm = X509CertificateSignatureAlgorithm.RsaSha1,
						TakeOwnershipOfKey = true
					};

					appCertificate = cngKey.CreateSelfSignedCertificate(certParams);

					var certPrivateCNG = new RSACng(appCertificate.GetCngPrivateKey());
					var certPrivateParams = certPrivateCNG.ExportParameters(true);

					File.WriteAllText("ClientCert.der", UASecurity.ExportPEM(appCertificate));
					File.WriteAllText("ClientKey.pem", UASecurity.ExportRSAPrivateKey(certPrivateParams));

					cryptPrivateKey = new RSACryptoServiceProvider();
					cryptPrivateKey.ImportParameters(certPrivateParams);
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

		static void Main(string[] args)
		{
			var appDesc = new ApplicationDescription(
				"urn:qs:DemoClient", "uri:qs:DemoClient", new LocalizedText("UA SDK client"),
				ApplicationType.Client, null, null, null);

			ApplicationDescription[] appDescs = null;
			EndpointDescription[] endpointDescs = null;

			//var client = new DemoClient("192.168.1.7", 7718, 10);
			var client = new DemoClient("127.0.0.1", 7718, 1000);
			client.Connect();
			client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);
			client.FindServers(out appDescs, new[] { "en" });
			client.GetEndpoints(out endpointDescs, new[] { "en" });
			client.Disconnect();

			// Check matching message security mode and security policy too
			// Lazy way to find server certificate is just grab any endpoint with one
			byte[] serverCert = endpointDescs
				.First(e => e.ServerCertificate != null && e.ServerCertificate.Length > 0)
				.ServerCertificate;

			var usernamePolicyDesc = endpointDescs
				.First(e => e.UserIdentityTokens.Any(t => t.TokenType == UserTokenType.UserName))
				.UserIdentityTokens.First(t => t.TokenType == UserTokenType.UserName)
				.PolicyId;

			// Create new client object to reset previous secure channel settings
			client = new DemoClient("127.0.0.1", 7718, 1000);
			var connectRes = client.Connect();
			client.OpenSecureChannel(MessageSecurityMode.SignAndEncrypt, SecurityPolicy.Basic256Sha256, serverCert);
			//var openRes = client.OpenSecureChannel(MessageSecurityMode.None, SecurityPolicy.None, null);
			var createRes = client.CreateSession(appDesc, "urn:qs:DemoClient", 120);
			var activateRes = client.ActivateSession(new UserIdentityAnonymousToken("0"), new[] { "en" });
			//var activateRes = client.ActivateSession(
			//	new UserIdentityUsernameToken(usernamePolicyDesc, "Username",
			//		(new UTF8Encoding()).GetBytes("Password"), Types.SignatureAlgorithmRsa15),
			//	new[] { "en" });

			DataValue[] dvs = null;
			client.Read(new ReadValueId[]
				{
					new ReadValueId(new NodeId(2, 1), NodeAttribute.Value, null, new QualifiedName(0, null)),
					new ReadValueId(new NodeId(2, 2), NodeAttribute.Value, null, new QualifiedName(0, null)),
					new ReadValueId(new NodeId(2, 3), NodeAttribute.Value, null, new QualifiedName(0, null)),
				}, out dvs);

			BrowseResult[] browseResults;
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
			}, 10000, out browseResults);

			uint[] respStatuses;
			client.Write(new WriteValue[]
				{
					new WriteValue(
						new NodeId(2, 0), NodeAttribute.Value,
						null, new DataValue(3.14159265, StatusCode.GoodClamped, DateTime.Now))
				}, out respStatuses);

			HistoryReadResult[] histResults = null;
			client.HistoryRead(new ReadRawModifiedDetails(false,
				new DateTime(2015, 12, 1),
				new DateTime(2015, 12, 2),
				100, true), TimestampsToReturn.Both, false,
				new HistoryReadValueId[]
				{
					new HistoryReadValueId(new NodeId(2, 1), null, new QualifiedName(), null),
					new HistoryReadValueId(new NodeId(2, 2), null, new QualifiedName(), null),
					new HistoryReadValueId(new NodeId(2, 3), null, new QualifiedName(), null),
				}, out histResults);

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

			uint subscrId;
			client.CreateSubscription(0, 1000, true, 0, out subscrId);

			// Second will have response BadSubscriptionIdInvalid
			client.SetPublishingMode(true, new[] { subscrId, 10u }, out respStatuses);

			uint respStatus;
			client.ModifySubscription(subscrId, 0, 100, true, 0, out respStatus);

			uint clientHandleEventMonitor = 0;
			var tagsMonitorId = new uint[3];
			for (int i = 0; i < 3; i++) { tagsMonitorId[i] = (uint)(1 + i); }

			MonitoredItemCreateResult[] monitorCreateResults;
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
				}, out monitorCreateResults);

			Console.ReadKey();

			// Last two should have BadMonitoredItemIdInvalid resp status
			client.DeleteMonitoredItems(subscrId, new uint[] { 0, 1, 2, 3, 4, 5 }, out respStatuses);
			client.DeleteSubscription(new[] { subscrId }, out respStatuses);

			client.Dispose();
		}
	}
}
