import java.util.Arrays;

public class TWINECipher {

    private final static int NUM_ROUNDS = 36;
    private final static int NUM_SUBKEYS = 9;
    private final static int BLOCK_SIZE = 8;
    private final static int KEY_SIZE = 16;

    private static int[] subKeys;

    public TWINECipher(byte[] key) {
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Key size should be " + KEY_SIZE + " bytes.");
        }
        subKeys = new int[NUM_SUBKEYS];
        for (int i = 0; i < NUM_SUBKEYS; i++) {
            subKeys[i] = (key[i * 2] & 0xFF) | ((key[i * 2 + 1] & 0xFF) << 8);
        }
    }

    public static byte[] encrypt(byte[] key, byte[] plaintext) {
        if (plaintext.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("Plaintext size should be " + BLOCK_SIZE + " bytes.");
        }
        int left = (plaintext[0] & 0xFF) | ((plaintext[1] & 0xFF) << 8);
        int right = (plaintext[2] & 0xFF) | ((plaintext[3] & 0xFF) << 8);

        for (int round = 0; round < NUM_ROUNDS; round++) {
            int temp = left;
            left = right ^ leftRotate(left, 1) ^ leftRotate(left, 9);
            right = sBox(right ^ subKeys[round]) ^ temp;
        }

        byte[] ciphertext = new byte[BLOCK_SIZE];
        ciphertext[0] = (byte) (left & 0xFF);
        ciphertext[1] = (byte) ((left >> 8) & 0xFF);
        ciphertext[2] = (byte) (right & 0xFF);
        ciphertext[3] = (byte) ((right >> 8) & 0xFF);
        return ciphertext;
    }

    public static byte[] decrypt(byte[] key, byte[] ciphertext) {
        if (ciphertext.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("Ciphertext size should be " + BLOCK_SIZE + " bytes.");
        }
        int left = (ciphertext[0] & 0xFF) | ((ciphertext[1] & 0xFF) << 8);
        int right = (ciphertext[2] & 0xFF) | ((ciphertext[3] & 0xFF) << 8);

        for (int round = NUM_ROUNDS - 1; round >= 0; round--) {
            int temp = right;
            right = left ^ leftRotate(right, 1) ^ leftRotate(right, 9);
            left = sBox(left ^ subKeys[round]) ^ temp;
        }

        byte[] plaintext = new byte[BLOCK_SIZE];
        plaintext[0] = (byte) (left & 0xFF);
        plaintext[1] = (byte) ((left >> 8) & 0xFF);
        plaintext[2] = (byte) (right & 0xFF);
        plaintext[3] = (byte) ((right >> 8) & 0xFF);
        return plaintext;
    }

    private static int leftRotate(int value, int shift) {
        return ((value << shift) | (value >>> (16 - shift))) & 0xFFFF;
    }

    private int rightRotate(int value, int shift) {
        return ((value >>> shift) | (value << (16 - shift))) & 0xFFFF;
    }

    private static int sBox(int value) {
        int[][] sbox = {
                {0xC, 0xA, 0xD, 0x3, 0xE, 0xB, 0xF, 0x7, 0x9, 0x1, 0x2, 0x6, 0x8, 0x0, 0x5, 0x4},
                {0x7, 0xC, 0xB, 0xD, 0xE, 0xF, 0x8, 0x9, 0x0, 0x3, 0xA, 0x1, 0x2, 0x6, 0x5, 0x4},
                {0xD, 0x8, 0xF, 0xC, 0xE, 0x9, 0x7, 0x0, 0x3, 0xA, 0x5, 0x2, 0x4, 0x6, 0x1, 0xB}
        };
        int row = (value >> 4) & 0x0F;
        int col = value & 0x0F;
        return sbox[row][col];
    }
}
