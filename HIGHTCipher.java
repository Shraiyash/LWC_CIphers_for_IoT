import java.util.Arrays;

public class HIGHTCipher {

    private final static int NUM_ROUNDS = 32;
    private final static int BLOCK_SIZE = 8;
    private final static int KEY_SIZE = 16;

    private static int[] subKeys;

    public HIGHTCipher(byte[] key) {
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Key size should be " + KEY_SIZE + " bytes.");
        }
        subKeys = new int[NUM_ROUNDS];
        for (int i = 0; i < NUM_ROUNDS; i++) {
            subKeys[i] = (key[i * 2] & 0xFF) | ((key[i * 2 + 1] & 0xFF) << 8);
        }
    }

    public static byte[] encrypt(byte[] key, byte[] plaintext) {
        if (plaintext.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("Plaintext size should be " + BLOCK_SIZE + " bytes.");
        }
        int left = (plaintext[0] & 0xFF) | ((plaintext[1] & 0xFF) << 8) | ((plaintext[2] & 0xFF) << 16) | ((plaintext[3] & 0xFF) << 24);
        int right = (plaintext[4] & 0xFF) | ((plaintext[5] & 0xFF) << 8) | ((plaintext[6] & 0xFF) << 16) | ((plaintext[7] & 0xFF) << 24);

        for (int round = 0; round < NUM_ROUNDS; round++) {
            right ^= leftRotate((left & subKeys[round % 8]) + right, 7);
            left ^= leftRotate((right | subKeys[round % 8]) + left, 9);
        }

        byte[] ciphertext = new byte[BLOCK_SIZE];
        ciphertext[0] = (byte) (left & 0xFF);
        ciphertext[1] = (byte) ((left >> 8) & 0xFF);
        ciphertext[2] = (byte) ((left >> 16) & 0xFF);
        ciphertext[3] = (byte) ((left >> 24) & 0xFF);
        ciphertext[4] = (byte) (right & 0xFF);
        ciphertext[5] = (byte) ((right >> 8) & 0xFF);
        ciphertext[6] = (byte) ((right >> 16) & 0xFF);
        ciphertext[7] = (byte) ((right >> 24) & 0xFF);
        return ciphertext;
    }

    public static byte[] decrypt(byte[] key, byte[] ciphertext) {
        if (ciphertext.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("Ciphertext size should be " + BLOCK_SIZE + " bytes.");
        }
        int left = (ciphertext[0] & 0xFF) | ((ciphertext[1] & 0xFF) << 8) | ((ciphertext[2] & 0xFF) << 16) | ((ciphertext[3] & 0xFF) << 24);
        int right = (ciphertext[4] & 0xFF) | ((ciphertext[5] & 0xFF) << 8) | ((ciphertext[6] & 0xFF) << 16) | ((ciphertext[7] & 0xFF) << 24);

        for (int round = NUM_ROUNDS - 1; round >= 0; round--) {
            left ^= rightRotate((right | subKeys[round % 8]) - left, 9);
            right ^= rightRotate((left & subKeys[round % 8]) - right, 7);
        }

        byte[] plaintext = new byte[BLOCK_SIZE];
        plaintext[0] = (byte) (left & 0xFF);
        plaintext[1] = (byte) ((left >> 8) & 0xFF);
        plaintext[2] = (byte) ((left >> 16) & 0xFF);
        plaintext[3] = (byte) ((left >> 24) & 0xFF);
        plaintext[4] = (byte) (right & 0xFF);
        plaintext[5] = (byte) ((right >> 8) & 0xFF);
        plaintext[6] = (byte) ((right >> 16) & 0xFF);
        plaintext[7] = (byte) ((right >> 24) & 0xFF);
        return plaintext;
    }

    public static int leftRotate(int value, int shift) {
        return ((value << shift) | (value >>> (32 - shift))) & 0xFFFFFFFF;
    }

    public static int rightRotate(int value, int shift) {
        return ((value >>> shift) | (value << (32 - shift))) & 0xFFFFFFFF;
    }
}
