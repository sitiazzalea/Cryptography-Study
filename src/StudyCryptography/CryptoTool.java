package StudyCryptography;


import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

/**
 *
 * @author Zaza
 */
public class CryptoTool {
    
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    
    }
     public static String convBin2Hex(byte[] data) {
        StringBuilder result = new StringBuilder();
        for (byte b : data) {
            result.append(String.format("%02x ", b));
        }
        return result.toString();       
    }
    
    public static String convBin2Base64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
        
    }
    
    public static String convBin2Str(byte[] data) {
        return new String(data) ;
    }
    
    public static byte[] convStr2Bin(String s) {
        return s.getBytes();
    }

    public static byte[] generateRandom(int size) {
        byte[] rand = new byte[size];
        new SecureRandom().nextBytes(rand);
        return rand;
    }
    
    public static byte[] encrypt(String algorithm, byte[] plainText, SecretKey key)
    throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
    BadPaddingException, IllegalBlockSizeException{
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(plainText);
        return cipherText;
    }
    
    public static byte[] decrypt(String algorithm, byte[] cipherText, SecretKey key)
    throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
    BadPaddingException, IllegalBlockSizeException{
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = cipher.doFinal(cipherText);
        return plainText;
    }
    
    
    public static void main(String[] arg) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
    BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException{
        String plainText = "putih kucing edan";
        SecretKey key = CryptoTool.generateKey(128);
        String algorithm = "AES/ECB/PKCS5Padding";
        byte[] cipherText = encrypt(algorithm, convStr2Bin(plainText), key);
        byte[] decryptedText = decrypt(algorithm, cipherText, key);
        System.out.println("cipher text (hex encoded): " + convBin2Hex(cipherText));
        System.out.println("decrypted text: " + convBin2Str(decryptedText));
    }   
}
