using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Linq;

namespace CryptographyStudy
{
    public class Hmac{
        public static byte[] generateHmac(string message, string hmacType, byte[] key){
            if (hmacType.Equals("HMACSHA256"))
            {
                HMACSHA256 hs256 = new HMACSHA256(key);
                return hs256.ComputeHash(Encoding.ASCII.GetBytes(message));
            }
            else if (hmacType.Equals("HMACSHA512")) {
                HMACSHA512 hs512 = new HMACSHA512(key);
                return hs512.ComputeHash(Encoding.ASCII.GetBytes(message));
            }
            else
            {
                throw new ArgumentException("Argumen yang Anda minta tidak tersedia");
            }
        }

        public static bool verifyHmac(string message, string hmacType, byte[] key, byte[]hmacToCompare) {
            byte[] hmac = generateHmac(message, hmacType, key);
            return hmac.SequenceEqual(hmacToCompare);
        } 
    }
}