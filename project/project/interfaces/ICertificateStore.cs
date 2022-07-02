using System.Security.Cryptography.X509Certificates;

namespace project.interfaces
{
    public interface ICertificateStore
    {
        void AddCertificate(X509Certificate2? cert);
    }
}
