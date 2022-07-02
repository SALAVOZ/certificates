using project.interfaces;
using System.Security.Cryptography.X509Certificates;

namespace project.certificateStore
{
    public class CertificateStore : ICertificateStore
    {
        private X509Store store;
        public CertificateStore()
        {
            X509Store store = new X509Store("michailStore");
        }

        public void AddCertificate(X509Certificate2? cert)
        {
            store.Add(cert);            store.Open(OpenFlags.ReadWrite);

        }
    }
}
