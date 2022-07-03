using Microsoft.AspNetCore.Mvc;
using project.certificateStore;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace project.services
{
    public class CERTIFICATE
    {
        public async Task<X509Certificate2> createSelfSignedCertificate(DateTimeOffset time)
        {
            var rsaKey = RSA.Create(2048);
            string subject = "CN=michail.ru";
            var certReq = new CertificateRequest(subject, rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            certReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certReq.PublicKey, false));
            var expirate = DateTimeOffset.Now.AddYears(5);
            var caCert = certReq.CreateSelfSigned(time, expirate);
            return caCert;
        }

        public async Task<X509Certificate2> createCertificate(X509Certificate2 caCert, DateTimeOffset time, RSA Key)
        {
            string subject = "CN=192.168.0.*";
            var certReq = new CertificateRequest(subject, Key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            certReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, false));
            certReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certReq.PublicKey, false));
            byte[] serialNumber = BitConverter.GetBytes(DateTime.Now.ToBinary());
            var clientCert = certReq.Create(caCert, time, time.AddYears(5), serialNumber);
            return clientCert;
        }

        public async void writeCert(X509Certificate2 cert, string name)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(cert.RawData, Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");
            File.WriteAllText(name, builder.ToString());
        }

        public async void writeKey(RSA key, string name)
        {
            string name_key = key.SignatureAlgorithm.ToUpper();
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"-----BEGIN {name_key} PRIVATE KEY-----");
            builder.AppendLine(Convert.ToBase64String(key.ExportRSAPrivateKey(), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine($"-----END {name_key} PRIVATE KEY-----");
            File.WriteAllText(name, builder.ToString());
        }
         
        public async void writePfx(X509Certificate2 Cert, RSA key)
        {
            var exportCert = new X509Certificate2(Cert.Export(X509ContentType.Cert), (string)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet).CopyWithPrivateKey(key);
            File.WriteAllBytes("client.pfx", exportCert.Export(X509ContentType.Pfx));
        }

        public async void writePKCS12(X509Certificate2 Cert, RSA key)
        {
            var exportCert = new X509Certificate2(Cert.Export(X509ContentType.Cert), (string)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet).CopyWithPrivateKey(key);
            File.WriteAllBytes("client.p12", exportCert.Export(X509ContentType.Pkcs12));
        }
    }
}
