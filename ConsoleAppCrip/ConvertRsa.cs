using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Serialization;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace RsaKeyConverter.Converter
{
    public static class RsaKeyConverter
    {
        public static string XmlToPem(string xml)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(xml);

                AsymmetricCipherKeyPair keyPair = Org.BouncyCastle.Security.DotNetUtilities.GetRsaKeyPair(rsa); // try get private and public key pair
                if (keyPair != null) // if XML RSA key contains private key
                {
                    PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
                    return FormatPem(Convert.ToBase64String(privateKeyInfo.GetEncoded()), "PRIVATE KEY");

                }

                RsaKeyParameters publicKey = Org.BouncyCastle.Security.DotNetUtilities.GetRsaPublicKey(rsa); // try get public key
                if (publicKey != null) // if XML RSA key contains public key
                {
                    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
                    return FormatPem(Convert.ToBase64String(publicKeyInfo.GetEncoded()), "PUBLIC KEY");
                }
            }

            throw new InvalidKeyException("Invalid RSA Xml Key");
        }

        public static string PublicXmlToPem(string xml)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(xml);

                RsaKeyParameters publicKey = Org.BouncyCastle.Security.DotNetUtilities.GetRsaPublicKey(rsa); // try get public key
                if (publicKey != null) // if XML RSA key contains public key
                {
                    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
                    return FormatPem(Convert.ToBase64String(publicKeyInfo.GetEncoded()), "PUBLIC KEY");
                }
            }

            throw new InvalidKeyException("Invalid RSA Xml Key");
        }

        private static string FormatPem(string pem, string keyType)
        {
            var sb = new StringBuilder();
            sb.AppendFormat("-----BEGIN {0}-----\n", keyType);

            int line = 1, width = 64;

            while ((line - 1) * width < pem.Length)
            {
                int startIndex = (line - 1) * width;
                int len = line * width > pem.Length
                              ? pem.Length - startIndex
                              : width;
                sb.AppendFormat("{0}\n", pem.Substring(startIndex, len));
                line++;
            }

            sb.AppendFormat("-----END {0}-----\n", keyType);
            return sb.ToString();
        }

        public static string PemToXml(string pem)
        {
            if (pem.StartsWith("-----BEGIN RSA PRIVATE KEY-----")
                || pem.StartsWith("-----BEGIN PRIVATE KEY-----"))
            {
                return GetXmlRsaKey(pem, obj =>
                {
                    if ((obj as RsaPrivateCrtKeyParameters) != null)
                        return DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)obj);
                    var keyPair = (AsymmetricCipherKeyPair)obj;
                    return DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)keyPair.Private);
                }, rsa => rsa.ToXmlString(true));
            }

            if (pem.StartsWith("-----BEGIN PUBLIC KEY-----"))
            {
                return GetXmlRsaKey(pem, obj =>
                {
                    var publicKey = (RsaKeyParameters)obj;
                    return DotNetUtilities.ToRSA(publicKey);
                }, rsa => rsa.ToXmlString(false));
            }

            throw new InvalidKeyException("Unsupported PEM format...");
        }

        private static string GetXmlRsaKey(string pem, Func getRsa, Func getKey)
        {
            using (var ms = new MemoryStream())
            using (var sw = new StreamWriter(ms))
            using (var sr = new StreamReader(ms))
            {
                sw.Write(pem);
                sw.Flush();
                ms.Position = 0;
                var pr = new PemReader(sr);
                object keyPair = pr.ReadObject();
                using (RSA rsa = getRsa(keyPair))
                {
                    var xml = getKey(rsa);
                    return xml;
                }
            }
        }
    }
}