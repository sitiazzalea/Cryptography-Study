using System.Security.Cryptography;

namespace CryptographyStudy
{
    public class RSA
    {

        public static byte[] encrypt(byte[] plaintext, RSAParameters key) {
            byte[] encrypted = new byte[plaintext.Length];

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider()) {
                rsa.ImportParameters(key);
                encrypted = rsa.Encrypt(plaintext, false);
            }
            return encrypted;
        } 

        public static byte[] decrypt(byte[] ciphertext, RSAParameters key)  {
            
        }
    }
}