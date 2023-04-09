package StudyCryptography;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 *
 * @author Zaza
 */
public class TugasModeOfOperation {

//    proses pembentukan blok, SPN network atau Feistel network terjadi di dalam fungsi ini
    public static byte[] blockCipher(byte[] plainText, byte[] key) throws Exception {     
        if (plainText.length != key.length) 
            throw new Exception("panjang array tidak sama");
        
        byte[] result = new byte [key.length];
        for (int i = 0; i < key.length; i++) {
            result[i] = (byte)((plainText[i] ^ key[i]) << 1);            
        }
        return result;
    }
    
//  proses pengenkripsian terjadi dengan pemanggilan fungsi block cipher sebanyak jumlah kelipatan blok size dan sekaligus mode 
//    mode of operation ECB
    public static byte[] encryptECB(byte[] plaintext, byte[] key) throws Exception {
//        assume there's no padding
        if (plaintext.length % key.length != 0) {
            throw new Exception("plaintext length is not the multiple of block size");
        }
        byte[] result = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i += key.length) {
            byte[] temp = Arrays.copyOfRange(plaintext, i, i + key.length);
            byte[] blockCipherResult = blockCipher(temp, key);
            for (int j = 0; j < blockCipherResult.length; j++) {
                result[i+j] = blockCipherResult[j];//penggabungan blok-blok dalam rangka ECB mode of operation
            }
        }
        return result;
    }
    
    public static byte[] encryptCBC(byte[] plaintext, byte[] key, byte[] iv) throws Exception{
//        assume there's no padding
        if (plaintext.length % key.length != 0 && key.length != iv.length) {
            throw new Exception("plaintext length is not the multiple of block size / iv length does not equal to key length");
        }
        byte[] result = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i += key.length) {
            byte[] plainBlock = Arrays.copyOfRange(plaintext, i, i + key.length);
//          XOR plaintext dengan iv
            byte[] xoredPlainBlock = new byte[plainBlock.length];
            for (int j = 0; j < iv.length; j++) {
                xoredPlainBlock[j] = (byte)(iv[j]^plainBlock[j]);
            }
            byte[] blockCipherResult = blockCipher(xoredPlainBlock, key);
            for (int j = 0; j < blockCipherResult.length; j++) {
                result[i+j] = blockCipherResult[j];            
            }
//          //replace iv with the cipher text to be used for iv of the next block
            iv = Arrays.copyOfRange(blockCipherResult, 0, blockCipherResult.length);
            
        }
        return result;
    }

    public static byte[] encryptCTR(byte[] plaintext, byte[] key, byte[] nonce) throws Exception {
 //        assume there's no padding
        if (plaintext.length % key.length != 0) {
            throw new Exception("plaintext length is not the multiple of block size");
        }
        
        final int ctrSize = 2; //because we use short 
        byte[] result = new byte[plaintext.length];
        
        short ctr = 0;
        byte[] bytesCTR;
        for (int i = 0; i < plaintext.length; i += key.length) { //the key length is the block size
            bytesCTR = ByteBuffer.allocate(ctrSize).putShort(ctr).array();
            byte[] nonceCTR = new byte[key.length];
            System.arraycopy(nonce, 0, nonceCTR, 0, nonce.length);        
            System.arraycopy(bytesCTR, 0, nonceCTR, nonce.length, bytesCTR.length);        
            byte[] blockCipherResult = blockCipher(nonceCTR, key);
            for (int j = 0; j < blockCipherResult.length; j++) {
                result[i+j] = (byte)(plaintext[i+j] ^ blockCipherResult[j]);            
            }
             
            ctr++; 
        }
        return result;
    }
    
    public static void main(String[] arg) throws Exception{
    
        byte[] plainText = {2, 98, 85, 90, 2, 98, 85, 90, 2, 98, 85, 90};
        byte[] key = {3, 97, 89, 90};

        byte[] resultECB = encryptECB(plainText, key);       
        System.out.println("ECB encrypted");
        for(byte r : resultECB) {
            System.out.print(r + " ");
        }
    
//      testing CBC
        byte[] iv = {51, 95, 99, 88};// initialization vector for cbc mode
        byte[] resultCBC = encryptCBC(plainText, key, iv);
        System.out.println("");
        System.out.println("CBC encrypted");
        for (byte rc : resultCBC) {
            System.out.print(rc + " ");
        }
        
//      testing ctr
        byte[] nonce = {24, 22};//nonce for ctr mode
        byte[] resultCTR = encryptCTR(plainText, key, nonce);
        System.out.println("");
        System.out.println("CTR encrypted");
        for (byte rct : resultCTR) {
            System.out.print(rct + " ");
        }
        
        
    }
    
}
