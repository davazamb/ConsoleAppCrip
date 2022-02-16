using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleAppCrip
{
    class RSA2048
    {
        public static void GenerateKeys(out string PublicKey, out string PrivateKey)
        {
            using (RSACryptoServiceProvider RSA2048 = new RSACryptoServiceProvider(2048))
            {
                RSA2048.PersistKeyInCsp = false;
                PublicKey = RSA2048.ToXmlString(false);
                PrivateKey = RSA2048.ToXmlString(true);
            }
        }

        public static string Encrypt(string PublicKey, string plain)
        {
            using (RSACryptoServiceProvider RSA2048 = new RSACryptoServiceProvider(2048))
            {
                RSA2048.PersistKeyInCsp = false;
                RSA2048.FromXmlString(PublicKey);
                return Convert.ToBase64String(RSA2048.Encrypt(Encoding.UTF8.GetBytes(plain), false));
            }
        }

        public static string Decrypt(string PrivateKey, string cipher)
        {
            using (RSACryptoServiceProvider RSA2048 = new RSACryptoServiceProvider(2048))
            {
                RSA2048.PersistKeyInCsp = false;
                RSA2048.FromXmlString(PrivateKey);
                return Encoding.UTF8.GetString(RSA2048.Decrypt(Convert.FromBase64String(cipher), false));
            }
        }
    }
}
