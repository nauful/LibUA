using LibUA;
using LibUA.Core;
using LibUA.Server;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SimpleServer
{
    internal class SimpleServerApplication : Application
    {
        private X509Certificate2 appCertificate;
        private RSA cryptPrivateKey;

        private Timer? timer;

        private NodeObject rootNode = new NodeObject(
            new NodeId(2, 0),
            new QualifiedName("SampleRoot"),
            new LocalizedText("Sample root"),
            new LocalizedText("The root element of the Simple Server sample."),
            (int)AttributeWriteMask.None,
            (int)AttributeWriteMask.None,
            0);

        private NodeVariable randomNumber = new NodeVariable(
            new NodeId(2, 1),
            new QualifiedName("RandomSample"),
            new LocalizedText("Random number"),
            new LocalizedText("Random number"),
            (int)AttributeWriteMask.None,
            (int)AttributeWriteMask.None,
            AccessLevel.CurrentRead,
            AccessLevel.CurrentRead,
            100.0,
            false,
            new NodeId(UAConst.Double),
            ValueRank.Scalar);

        private Random random = new Random();

        public SimpleServerApplication()
        {
            LoadCertificateAndPrivateKey(out appCertificate, out cryptPrivateKey);

            SetupSampleAddressSpace();
        }

        #region minimum requirement

        public override X509Certificate2 ApplicationCertificate => appCertificate;

        public override RSA ApplicationPrivateKey => cryptPrivateKey;

        public override ApplicationDescription GetApplicationDescription(string endpointUrlHint)
        {
            Console.WriteLine(endpointUrlHint);
            return new ApplicationDescription(
                $"urn:quantensystems:libua:SimpleServerSample:{Environment.MachineName}",
                "urn:quantensystems:libua:SimpleServerSample",
                new LocalizedText("en-US", "Simple Server sample"),
                ApplicationType.Server,
                null,
                null,
                new string[] { endpointUrlHint });
        }

        public override IList<EndpointDescription> GetEndpointDescriptions(string endpointUrlHint)
        {
            var certificate = ApplicationCertificate.Export(X509ContentType.Cert);

            return new EndpointDescription[] {
                new EndpointDescription(
                    endpointUrlHint,
                    GetApplicationDescription(endpointUrlHint),
                    certificate,
                    MessageSecurityMode.None,
                    Types.SLSecurityPolicyUris[(int)SecurityPolicy.None],
                    new UserTokenPolicy[]
                    {
                        new UserTokenPolicy("0", UserTokenType.Anonymous, null, null, Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]),
                    },
                    Types.TransportProfileBinary,
                    0),
            };
        }

        #endregion

        #region add custom nodes

        protected override DataValue HandleReadRequestInternal(NodeId id)
        {
            // override default namespaces
            if (id.Equals(new NodeId(UAConst.Server_NamespaceArray)))
            {
                return new DataValue(
                    new string[] {
                        "http://opcfoundation.org/UA/",
                        "http://quantensystems.com/SimpleServer"
                    },
                    StatusCode.Good);
            }

            // read our custom node
            if (id.Equals(randomNumber.Id))
            {
                return new DataValue(
                    randomNumber.Value,
                    StatusCode.Good,
                    DateTime.Now,
                    DateTime.Now);
            }

            return base.HandleReadRequestInternal(id);
        }

        private void SetupSampleAddressSpace()
        {
            // add our root item as subitem of the Objects folder
            var objectsFolderId = new NodeId(UAConst.ObjectsFolder);

            AddressSpaceTable[objectsFolderId]
                .References
                .Add(new ReferenceNode(new NodeId(UAConst.Organizes), rootNode.Id, false));

            rootNode
                .References
                .Add(new ReferenceNode(new NodeId(UAConst.Organizes), objectsFolderId, true));

            AddressSpaceTable.TryAdd(rootNode.Id, rootNode);

            // add custom node
            rootNode.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), randomNumber.Id, false));
            randomNumber.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), rootNode.Id, true));

            AddressSpaceTable.TryAdd(randomNumber.Id, randomNumber);

            // add timer to update the custom node
            timer = new Timer(
                state => {
                    randomNumber.Value = random.NextDouble();
                    MonitorNotifyDataChange(randomNumber.Id, new DataValue(randomNumber.Value, StatusCode.Good, DateTime.Now, DateTime.Now));
                },
                null,
                1000,
                250
            );
        }

        #endregion

        #region helper

        private static void LoadCertificateAndPrivateKey(out X509Certificate2 appCertificate, out RSA cryptPrivateKey)
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

        #endregion
    }
}
