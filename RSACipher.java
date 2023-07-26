import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;

public class RSACipher {

    public static void main(String[] args) throws Exception {
        // Generate RSA key pair
        KeyPair keyPair = generateRSAKeyPair();

        // Get the public and private keys
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        // Sample plaintext message
        String plaintextMessage = "Hello, RSA!";

        // Encryption
        byte[] ciphertext = encryptRSA(publicKey, plaintextMessage);
        System.out.println("Ciphertext: " + new String(ciphertext));

        // Decryption
        String decryptedMessage = decryptRSA(privateKey, ciphertext);
        System.out.println("Decrypted Message: " + decryptedMessage);
    }

    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Key size can vary depending on security requirements
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encryptRSA(RSAPublicKey publicKey, String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext.getBytes());
    }

    public static String decryptRSA(RSAPrivateKey privateKey, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        return new String(decryptedBytes);
    }
}
