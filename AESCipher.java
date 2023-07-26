import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AESCipher {

    private static final String AES_ALGORITHM = "AES";
    private static final int KEY_SIZE = 128;
    private static final int BLOCK_SIZE = 128;

    public static byte[] encrypt(byte[] key, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        SecretKeySpec secretKeySpec = generateSecretKeySpec(key);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] key, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        SecretKeySpec secretKeySpec = generateSecretKeySpec(key);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(ciphertext);
    }

    private static SecretKeySpec generateSecretKeySpec(byte[] key) {
        return new SecretKeySpec(key, AES_ALGORITHM);
    }
}
