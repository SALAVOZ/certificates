using Microsoft.AspNetCore.Mvc;
using project.certificateStore;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace project.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class CertificateController
    {
        private CertificateStore _certificateStore;
        public CertificateController()
        {
            
        }

        [HttpGet]
        [Route("selfsigned")]
        public void createSelfSignedCertificate()
        {
            // Генерируем ассиметричный ключ
            var rsaKey = RSA.Create(2048);

            // Описываем субъект сертификации
            string subject = "CN=michail.ru";

            // Создаём запрос на сетификат
            // Режим Pkcs используется по умолчанию
            var certReq = new CertificateRequest(subject, rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // Дополнительно настраиваем запрос
            certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            certReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certReq.PublicKey, false));

            var expirate = DateTimeOffset.Now.AddYears(5);
            var caCert = certReq.CreateSelfSigned(DateTimeOffset.Now, expirate);
            addAtStore(caCert);
        }

        [HttpGet]
        [Route("cert")]
        public void createCertificate(X509Certificate2? caCert)
        {
            var clientKey = RSA.Create(2048);
            string subject = "CN=192.168.0.*";
            var clientReq = new CertificateRequest(subject, clientKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            clientReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            clientReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, false));
            clientReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(clientReq.PublicKey, false));

            // НАЗНАЧАЕМ СЕРТИФИКАТУ СЕРИЙНЫЙ НОМЕР
            byte[] serialNumber = BitConverter.GetBytes(DateTime.Now.ToBinary());

            var expirate = DateTimeOffset.Now.AddYears(5);
            var clientCert = clientReq.Create(caCert, DateTimeOffset.Now, expirate, serialNumber);

            StorePfx(clientCert, clientKey);
        }


        public void StoreCertificate(X509Certificate2? clientCert)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            builder.AppendLine(Convert.ToBase64String(clientCert.RawData, Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");
            File.WriteAllText("public.crt", builder.ToString());
        }

        public void StorePrivateKey(RSA clientKey)
        {
            string name = clientKey.SignatureAlgorithm.ToUpper();
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"-----BEGIN {name} PRIVATE KEY-----");
            builder.AppendLine(Convert.ToBase64String(clientKey.ExportRSAPrivateKey(), Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine($"-----END {name} PRIVATE KEY-----");
            File.WriteAllText("private.key", builder.ToString());
        }

        private void StorePfx(X509Certificate2? clientCert, RSA clientKey)
        {
            var exportCert = new X509Certificate2(clientCert.Export(X509ContentType.Cert), (string)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet).CopyWithPrivateKey(clientKey);
            File.WriteAllBytes("client.pfx", exportCert.Export(X509ContentType.Pfx));
        }

        private void addAtStore(X509Certificate2? cert)
        {
            X509Store store = new X509Store("michailStore");
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
        }
    }
}
