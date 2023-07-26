import java.nio.charset.StandardCharsets;

public class MainLWCCiphers {
    public static void main(String[] args) throws Exception {
        byte[] plaintext = "Hello, Lightweight Ciphers!".getBytes(StandardCharsets.UTF_8);
        byte[] key = "ThisIsA128BitKey".getBytes(StandardCharsets.UTF_8);

        // TWINE Cipher
        byte[] twineCiphertext = TWINECipher.encrypt(key, plaintext);
        byte[] twineDecryptedText = TWINECipher.decrypt(key, twineCiphertext);
        System.out.println("TWINE Ciphertext: " + new String(twineCiphertext, StandardCharsets.UTF_8));
        System.out.println("TWINE Decrypted Text: " + new String(twineDecryptedText, StandardCharsets.UTF_8));

        // HIGHT Cipher
        byte[] hightCiphertext = HIGHTCipher.encrypt(key, plaintext);
        byte[] hightDecryptedText = HIGHTCipher.decrypt(key, hightCiphertext);
        System.out.println("HIGHT Ciphertext: " + new String(hightCiphertext, StandardCharsets.UTF_8));
        System.out.println("HIGHT Decrypted Text: " + new String(hightDecryptedText, StandardCharsets.UTF_8));

        // CLEFIA Cipher
        byte[] clefiaCiphertext = CLEFIACipher.encrypt(key, plaintext);
        byte[] clefiaDecryptedText = CLEFIACipher.decrypt(key, clefiaCiphertext);
        System.out.println("CLEFIA Ciphertext: " + new String(clefiaCiphertext, StandardCharsets.UTF_8));
        System.out.println("CLEFIA Decrypted Text: " + new String(clefiaDecryptedText, StandardCharsets.UTF_8));

        // AES Cipher
        byte[] AESCiphertext = AESCipher.encrypt(key, plaintext);
        byte[] AESDecryptedText = AESCipher.decrypt(key, AESCiphertext);
        System.out.println("AES Ciphertext: " + new String(AESCiphertext, StandardCharsets.UTF_8));
        System.out.println("AES Decrypted Text: " + new String(AESDecryptedText, StandardCharsets.UTF_8));

        // RSA Cipher
        byte[] RSACiphertext = AESCipher.encrypt(key, plaintext);
        byte[] RSADecryptedText = AESCipher.decrypt(key, RSACiphertext);
        System.out.println("RSA Ciphertext: " + new String(RSACiphertext, StandardCharsets.UTF_8));
        System.out.println("RSA Decrypted Text: " + new String(RSADecryptedText, StandardCharsets.UTF_8));

    }
}
