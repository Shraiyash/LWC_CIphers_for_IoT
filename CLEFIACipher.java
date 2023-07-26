import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class CLEFIACipher {

    private static final int KEY_SIZE = 128;
    private static final int BLOCK_SIZE = 128;

    public static byte[] encrypt(byte[] key, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("CLEFIA/ECB/NoPadding");
        SecretKeySpec secretKeySpec = generateSecretKeySpec(key);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] key, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("CLEFIA/ECB/NoPadding");
        SecretKeySpec secretKeySpec = generateSecretKeySpec(key);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(ciphertext);
    }

    private static SecretKeySpec generateSecretKeySpec(byte[] key) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hashedKey = sha256.digest(key);
        return new SecretKeySpec(Arrays.copyOf(hashedKey, KEY_SIZE / 8), "CLEFIA");
    }
}
