using Microsoft.AspNetCore.Mvc;
using project.certificateStore;
using project.services;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace project.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class CertificateController
    {
        //private CertificateStore _certificateStore;
        IHttpClientFactory _clientFactory;
        CERTIFICATE _certificate;
        public CertificateController(IHttpClientFactory clientFactory)
        {
            _clientFactory = clientFactory;
            _certificate = new CERTIFICATE();
        }

        [HttpGet]
        [Route("cert")]
        public async void Handler()
        {
            DateTimeOffset time = DateTimeOffset.Now;
            var caCert = await _certificate.createSelfSignedCertificate(time);
            var clientKey = await createKey();
            var serverKey = await createKey();
            var clientCert = await _certificate.createCertificate(caCert, time, clientKey);
            var serverCert = await _certificate.createCertificate(caCert, time, serverKey);


            //SocketsHttpHandler handler = new SocketsHttpHandler();
            //handler.SslOptions.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
            //{
            //    chain = new X509Chain(false);
            //    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            //    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            //    chain.ChainPolicy.ExtraStore.Add(caCert);
            //    var serverСert = new X509Certificate2(certificate);
            //    return chain.Build(serverСert);
            //};
            //handler.SslOptions.ClientCertificates = new X509CertificateCollection() { clientCert };
            //HttpClient client = new HttpClient(handler);
            //var resp = await client.GetAsync("https://yandex.ru");

            // СОЗДАДИМ СЕРТИФИКАТЫ
            _certificate.writeCert(caCert, "//etc//nginx//ssl//caCert.crt");
            _certificate.writeCert(clientCert, "//etc//nginx//ssl//public.crt");
            _certificate.writeKey(clientKey, "//etc//nginx//ssl//private.key");
        }

        public async Task<RSA> createKey()
        {
            return RSA.Create(2048);
        }

        //public async Task<X509Certificate2> createSelfSignedCertificate(DateTimeOffset time)
        //{
        //    var rsaKey = RSA.Create(2048);
        //    string subject = "CN=myauthority.ru";
        //    var certReq = new CertificateRequest(subject, rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        //    certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        //    certReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certReq.PublicKey, false));
        //    var expirate = DateTimeOffset.Now.AddYears(5);
        //    var caCert = certReq.CreateSelfSigned(time, expirate);
        //    return caCert;
        //}

        //public async Task<X509Certificate2> createCertificate(X509Certificate2 caCert, DateTimeOffset time, RSA Key)
        //{
        //    string subject = "CN=192.168.0.*";
        //    var certReq = new CertificateRequest(subject, Key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        //    certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        //    certReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, false));
        //    certReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certReq.PublicKey, false));
        //    byte[] serialNumber = BitConverter.GetBytes(DateTime.Now.ToBinary());
        //    var clientCert = certReq.Create(caCert, time, time.AddYears(5), serialNumber);
        //    return clientCert;
        //}

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

        //[HttpGet]
        //[Route("selfsigned")]
        //public async void createSelfSignedCertificate()
        //{
        //    // Генерируем ассиметричный ключ
        //    var rsaKey = RSA.Create(2048);

        //    // Описываем субъект сертификации
        //    string subject = "CN=michail.ru";

        //    // Создаём запрос на сетификат
        //    // Режим Pkcs используется по умолчанию
        //    var certReq = new CertificateRequest(subject, rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        //    // Дополнительно настраиваем запрос
        //    certReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        //    certReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certReq.PublicKey, false));
        //    var time = DateTimeOffset.Now;
        //    var expirate = DateTimeOffset.Now.AddYears(5);
        //    var caCert = certReq.CreateSelfSigned(time, expirate);

        //    StringBuilder builder1 = new StringBuilder();
        //    builder1.AppendLine("-----BEGIN CERTIFICATE-----");
        //    builder1.AppendLine(Convert.ToBase64String(caCert.RawData, Base64FormattingOptions.InsertLineBreaks));
        //    builder1.AppendLine("-----END CERTIFICATE-----");
        //    File.WriteAllText("caCert.crt", builder1.ToString());


        //    addAtStore(caCert);
        //    var clientCert = createCertificate(caCert, time);

        //    SocketsHttpHandler handler = new SocketsHttpHandler();
        //    X509Chain chain = new X509Chain(false);
        //    handler.SslOptions.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
        //    {
        //        //X509Chain chain = new X509Chain(false);
        //        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        //        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
        //        chain.ChainPolicy.ExtraStore.Add(caCert);
        //        var serverСert = new X509Certificate2(certificate);
        //        return chain.Build(serverСert);
        //    };
        //    handler.SslOptions.ClientCertificates = new X509CertificateCollection() { clientCert };
        //    HttpClient client = new HttpClient(handler);
        //    var resp =  await client.GetAsync("http://www.sbup.com/wiki/HTTP");
        //}

        ////[HttpGet]
        ////[Route("cert")]
        //public X509Certificate2? createCertificate(X509Certificate2? caCert, DateTimeOffset signedTime)
        //{
        //    var clientKey = RSA.Create(2048);

        //string name = clientKey.SignatureAlgorithm.ToUpper();
        //StringBuilder builder = new StringBuilder();
        //builder.AppendLine($"-----BEGIN {name} PRIVATE KEY-----");
        //builder.AppendLine(Convert.ToBase64String(clientKey.ExportRSAPrivateKey(), Base64FormattingOptions.InsertLineBreaks));
        //builder.AppendLine($"-----END {name} PRIVATE KEY-----");
        //File.WriteAllText("private.key", builder.ToString());

        //string subject = "CN=192.168.0.*";
        //var clientReq = new CertificateRequest(subject, clientKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        //clientReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        //clientReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, false));
        //clientReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(clientReq.PublicKey, false));

        //// НАЗНАЧАЕМ СЕРТИФИКАТУ СЕРИЙНЫЙ НОМЕР
        //byte[] serialNumber = BitConverter.GetBytes(DateTime.Now.ToBinary());

        //var expirate = signedTime.AddYears(5);
        //var clientCert = clientReq.Create(caCert, signedTime, expirate, serialNumber);

        //StringBuilder builder1 = new StringBuilder();
        //builder1.AppendLine("-----BEGIN CERTIFICATE-----");
        //builder1.AppendLine(Convert.ToBase64String(clientCert.RawData, Base64FormattingOptions.InsertLineBreaks));
        //builder1.AppendLine("-----END CERTIFICATE-----");
        //File.WriteAllText("public.crt", builder1.ToString());

        //    StorePfx(clientCert, clientKey);
        //    var exportCert = new X509Certificate2(clientCert.Export(X509ContentType.Cert), (string)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet).CopyWithPrivateKey(clientKey);
        //    File.WriteAllBytes("client.pfx", exportCert.Export(X509ContentType.Pfx));
        //    return clientCert;
        //}


        //public void StoreCertificate(X509Certificate2? clientCert)
        //{
        //    StringBuilder builder = new StringBuilder();
        //    builder.AppendLine("-----BEGIN CERTIFICATE-----");
        //    builder.AppendLine(Convert.ToBase64String(clientCert.RawData, Base64FormattingOptions.InsertLineBreaks));
        //    builder.AppendLine("-----END CERTIFICATE-----");
        //    File.WriteAllText("public.crt", builder.ToString());
        //}

        //public void StorePrivateKey(RSA clientKey)
        //{
        //    string name = clientKey.SignatureAlgorithm.ToUpper();
        //    StringBuilder builder = new StringBuilder();
        //    builder.AppendLine($"-----BEGIN {name} PRIVATE KEY-----");
        //    builder.AppendLine(Convert.ToBase64String(clientKey.ExportRSAPrivateKey(), Base64FormattingOptions.InsertLineBreaks));
        //    builder.AppendLine($"-----END {name} PRIVATE KEY-----");
        //    File.WriteAllText("private.key", builder.ToString());
        //}

        //private void StorePfx(X509Certificate2? clientCert, RSA clientKey)
        //{
        //    var exportCert = new X509Certificate2(clientCert.Export(X509ContentType.Cert), (string)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet).CopyWithPrivateKey(clientKey);
        //    File.WriteAllBytes("client.pfx", exportCert.Export(X509ContentType.Pfx));
        //}

        //private void addAtStore(X509Certificate2? cert)
        //{
        //    X509Store store = new X509Store("michailStore");
        //    store.Open(OpenFlags.ReadWrite);
        //    store.Add(cert);
        //}
    }
}
