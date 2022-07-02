using project.interfaces;
using System.Security.Cryptography.X509Certificates;

namespace project.certificateStore
{
    public class CertificateStore : ICertificateStore
    {
        private X509Store store;
        public CertificateStore(X509Certificate2? cert)
        {
            X509Store store = new X509Store("michailStore");
            store.Open(OpenFlags.ReadWrite);
        }

        public void AddCertificate(X509Certificate2? cert)
        {
            store.Add(cert);
        }
    }
}
