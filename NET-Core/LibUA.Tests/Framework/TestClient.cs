using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LibUA.Tests
{
    public class TestClient : Client, IDisposable
    {
        private X509Certificate2? appCertificate = null;
        private RSA? cryptPrivateKey = null;
        public override X509Certificate2? ApplicationCertificate
        {
            get { return appCertificate; }
        }

        public override RSA? ApplicationPrivateKey
        {
            get { return cryptPrivateKey; }
        }

        public TestClient(string Target, int Port, int Timeout) : base(Target, Port, Timeout)
        {
            LoadCertificateAndPrivateKey();
        }

        public new void Dispose()
        {
            base.Dispose();
            GC.SuppressFinalize(this);
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
}
