using System.Text;
using System.Security.Cryptography;

namespace CryptographyStudy
{
    public class AesStudy {

        public static byte[] encryptCBC(byte[] plainText, byte[] key, byte[]iv){
            byte[] result = new byte[plainText.Length + iv.Length];

            Aes aes = Aes.Create();
            aes.Key = key;
            // aes.Mode = CipherMode.CBC;
            System.Security.Cryptography.PaddingMode paddingMode = System.Security.Cryptography.PaddingMode.PKCS7;
            result = aes.EncryptCbc(plainText, iv, paddingMode);
            return result;
        }

        public static byte[] decryptCBC(byte[] cipher, byte[] key, byte[] iv){
            byte[] result = new byte[cipher.Length + iv.Length];
            Aes aes = Aes.Create();
            aes.Key = key;
            // aes.Mode = CipherMode.CBC;
            System.Security.Cryptography.PaddingMode paddingMode = System.Security.Cryptography.PaddingMode.PKCS7;
            result = aes.DecryptCbc(cipher, iv, paddingMode);
            return result;
        }

        public static void encryptGCM(byte[] key, byte[] nonce, byte[] plainText, byte[] additionalData, byte[] tag,  byte[] result) {
            // panjang tag 16 bit       
            AesGcm ag = new AesGcm(key);
            ag.Encrypt(nonce, plainText, result, tag, additionalData);
        }

        public static void decryptGCM(byte[] key, byte[] nonce,byte[] cipherText, byte[] additionalData, byte[] tag, byte[] result) {
            AesGcm ag = new AesGcm(key);
            ag.Decrypt(nonce, cipherText, tag, result, additionalData);
        }

    }
    
}