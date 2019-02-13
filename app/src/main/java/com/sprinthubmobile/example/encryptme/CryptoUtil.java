package com.sprinthubmobile.example.encryptme;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CryptoUtil {
    public static final String TRANSFORMATION = "AES/GCM/NoPadding";

    public static void encrypt(SecretKey secretKey, File inputFile, File outputFile) throws CryptoException {
        doCrypto(Cipher.ENCRYPT_MODE, secretKey, inputFile, outputFile);
    }

    public static void decrypt(SecretKey secretKey, File inputFile, File outputFile) throws CryptoException {
        doCrypto(Cipher.DECRYPT_MODE, secretKey, inputFile, outputFile);
    }

    private static void doCrypto(int cypherMode, SecretKey secretKey, File inputFile, File outputFile) throws CryptoException {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(cypherMode, secretKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));

            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            byte[] outputBytes = cipher.doFinal(inputBytes);

            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);

            inputStream.close();
            outputStream.close();
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException
                | BadPaddingException | IllegalBlockSizeException | IOException ex) {
            throw new CryptoException("Error encrypting/decrypting file!", ex);
        }
    }


    public static byte[] encrypt(SecretKey secretKey, byte[] input) throws CryptoException {
        return doCrypto(Cipher.ENCRYPT_MODE, secretKey, input);
    }

    public static byte[] decrypt(SecretKey secretKey, byte[] inputBytes) throws CryptoException {
        return doCrypto(Cipher.DECRYPT_MODE, secretKey, inputBytes);
    }

    /**
     * Use to encrypt/decrypt simple string for testing purposes
     * @param cypherMode
     * @param secretKey
     * @param input
     * @return
     * @throws CryptoException
     */
    private static byte[] doCrypto(int cypherMode, SecretKey secretKey, byte[] input) throws CryptoException {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(cypherMode, secretKey, new IvParameterSpec(new byte[cipher.getBlockSize()]));

            return cipher.doFinal(input);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException
                | BadPaddingException | IllegalBlockSizeException ex) {
            throw new CryptoException("Error encrypting/decrypting file!", ex);
        }
    }
}
