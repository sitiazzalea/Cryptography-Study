using System;
using System.Security.Cryptography;
using System.Text;

namespace CryptographyStudy
{
    class Program
    {
        public static void testHmac() {
            Console.WriteLine("Enter your string to hash: ");
            string input = Console.ReadLine();
            Console.WriteLine("Choose between HMACSHA256 or HMACSHA512: ");
            string hmType = Console.ReadLine();
            byte[] keyHmac = Tools.generateRandomNumber(32);
            Console.WriteLine("Hashed result:");
            Console.WriteLine(Tools.bin2str(Hashing.toSHA256(input)));
            Console.WriteLine("Key:");
            Console.WriteLine(Tools.bin2str(keyHmac));
            Console.WriteLine("HMAC result:");
            byte[] hmacResult = Hmac.generateHmac(input, hmType, keyHmac);
            hmacResult[0] = 1; //tamper the hmac
            Console.WriteLine(Tools.bin2str(hmacResult));
            bool verified = Hmac.verifyHmac(input, hmType, keyHmac,hmacResult);
            Console.WriteLine(verified);
        }

        public static void testAESCBC() {
            string message = "kriptografi di C#kriptografi di C#kriptografi di C#";
            byte[] plainTextInByte = Tools.str2bin(message);
            byte[] key = Tools.generateRandomNumber(32);
            byte[] iv = Tools.generateRandomNumber(16);
            byte[] cipherText = AesStudy.encryptCBC(plainTextInByte, key, iv);
            Console.WriteLine("Key:");
            Console.WriteLine(Tools.bin2hex(key));
            Console.WriteLine("IV:");
            Console.WriteLine(Tools.bin2hex(iv));
            Console.WriteLine("Cipher text in hexa:");
            Console.WriteLine(Tools.bin2hex(cipherText));    

            byte[] decryptedText = AesStudy.decryptCBC(cipherText, key, iv);
            Console.WriteLine("Cipher text in hexa:");
            Console.WriteLine(Tools.bin2str(decryptedText));                
        }

        public static void testAESGCM() {
            byte[] key = Tools.generateRandomNumber(16);
            byte[] nonce = Tools.generateRandomNumber(12);
            byte[] tag = new byte[16];
            string plainText = "TestingAESGCM";
            string additionalData = "putih";
            byte[] plainTextInBytes = Tools.str2bin(plainText);
            byte[] addDataInBytes = Tools.str2bin(additionalData);
            byte[] cipherText = new byte[plainTextInBytes.Length];
            // public static void encryptGCM(byte[] key, byte[] nonce, byte[] plainText, byte[] additionalData, byte[] tag,  byte[] result) {
            AesStudy.encryptGCM(key, nonce, plainTextInBytes, addDataInBytes, tag, cipherText);
            Console.WriteLine(Tools.bin2hex(cipherText));
            Console.WriteLine(Tools.bin2hex(tag));

        // public static void decryptGCM(byte[] key, byte[] nonce,byte[] cipherText, byte[] additionalData, byte[] tag, byte[] result) {
            byte[] decryptText = new byte[cipherText.Length];
            AesStudy.decryptGCM(key, nonce, cipherText, addDataInBytes, tag, decryptText);
            Console.WriteLine(Tools.bin2str(decryptText));
        }

        public static void testRSA() {
            string plainText = "Hello World!!!";
            byte[] plainTextInBytes = Tools.str2bin(plainText);
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);  
            var rsaParams =  rsa.ExportParameters(false);     
            Console.WriteLine(Tools.bin2hex(RSA.encrypt(plainTextInBytes, rsaParams)));

        }

        public static string rsaParamstoString(RSAParameters rsap) {
            StringBuilder sb = new StringBuilder();
            sb.AppendFormat("eksponen(e): {0}{1}", Tools.bin2hex(rsap.Exponent), "\n");
            // sb.AppendFormat("eksponen(d): {0}{1}", Tools.bin2hex(rsap.D ?? new byte[] {0}) , "\n");
            sb.AppendFormat("eksponen(d): {0}{1}", Tools.bin2hex(rsap.D) ?? "Not Applicable" , "\n");
            // sb.AppendFormat("eksponen(d) mod (p-1): {0}{1}", Tools.bin2hex(rsap.DP), "\n");
            // sb.AppendFormat("eksponen(d) mod (q-1): {0}{1}", Tools.bin2hex(rsap.DQ), "\n");
            // sb.AppendFormat("1 mod p: {0}{1}", Tools.bin2hex(rsap.InverseQ), "\n");
            // sb.AppendFormat("modulus: {0}{1}", Tools.bin2hex(rsap.Modulus), "\n");
            // sb.AppendFormat("P: {0}{1}", Tools.bin2hex(rsap.P), "\n");
            // sb.AppendFormat("Q: {0}{1}", Tools.bin2hex(rsap.Q), "\n");
            return sb.ToString();
        }
        public static void Main(string[] args)
        {
            // testAESGCM();
            // testRSA();
            // string plainText = "Hello World!!!";
            // byte[] plainTextInBytes = Tools.str2bin(plainText);
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);  
            var rsaParams =  rsa.ExportParameters(false);     
            // Console.WriteLine("eksponen(e): {0}", Tools.bin2hex(rsaParams.Exponent));
            // Console.WriteLine("eksponen(d): {0}", Tools.bin2hex(rsaParams.D));
            // Console.WriteLine("eksponen(d) mod (p-1): {0}", Tools.bin2hex(rsaParams.DP));
            // Console.WriteLine("eksponen(d) mod (q-1): {0}", Tools.bin2hex(rsaParams.DQ));
            // Console.WriteLine("1 mod p: {0}", Tools.bin2hex(rsaParams.InverseQ));
            // Console.WriteLine("modulus: {0}", Tools.bin2hex(rsaParams.Modulus));
            // Console.WriteLine("P: {0}", Tools.bin2hex(rsaParams.P));
            // Console.WriteLine("Q: {0}", Tools.bin2hex(rsaParams.Q));
            // Console.WriteLine(Tools.bin2hex(RSA.encrypt(plainTextInBytes, rsaParams)));
            // Console.WriteLine("plaintext: " + plainText + ", length: " + plainText.Length);
            // Console.WriteLine("plaintext: {0}, length: {1}", plainText, plainText.Length);
            // Console.WriteLine($"plaintext: {plainText}, length: {plainText.Length}");
            Console.WriteLine(rsaParamstoString(rsaParams));
        }
    }
}