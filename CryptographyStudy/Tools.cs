using System.Text;
using System.Security.Cryptography;

namespace CryptographyStudy {
    public static class Tools{
        public static string bin2str(byte[] ba)
        {
            return Encoding.UTF8.GetString(ba, 0, ba.Length);
        }

        public static string? bin2hex(byte[]? ba) {
            // StringBuilder hex = new StringBuilder(ba.Length * 2);
            // foreach (byte b in ba)
            //     hex.AppendFormat("{0:x2}", b);
            // return hex.ToString();
            return BitConverter.ToString(ba) ?? null;
        }

        public static byte[] str2bin(string str){
            // byte[] testInByte = Tools.str2bin(test); 
            // foreach(byte b in testInByte) {
            //     Console.WriteLine(b.ToString());
            // }
            return Encoding.UTF8.GetBytes(str);
        }

        public static byte[] generateRandomNumber(int keySize)
        {
            byte[] result = new byte[keySize];
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(result);
            return result;
        }
    }
}