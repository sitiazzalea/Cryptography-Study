using System.Security.Cryptography;
using System.Text;

namespace CryptographyStudy 
{
    public class Hashing {

        public static byte[] toSHA256(string s) {
            using var sha256 = SHA256.Create();
            byte[] shaInByte = sha256.ComputeHash(Encoding.UTF8.GetBytes(s));
            return shaInByte;
        }
    }
}