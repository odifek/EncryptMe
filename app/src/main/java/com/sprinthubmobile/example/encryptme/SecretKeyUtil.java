package com.sprinthubmobile.example.encryptme;

import android.content.Context;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * A utility class used to handle generation and retrieval of {@link SecretKey}s for our encryption and decryption tasks
 * <p>
 *     <ul>
 *         <li>First call {@link #generateSecretKey()} to generate the key</li>
 *         <li>Then store or save the key using {@link #saveKeyToKeyStore(Context, SecretKey, String, String)}</li>
 *         <li>The above two should be done only on fresh user sign in. Like when the app is installed newly,
 *              or when the user resets the app and would sign in again</li>
 *         <li>Then on subsequent occasions when you want to run encryption or decryption, call {@link #getSecretKeyFromKeyStore(Context, String, String)}
 *              supplying the password and alias </li>
 *     </ul>
 * </p>
 */
public class SecretKeyUtil {

    /**
     * Used to generate a 256 bit length {@link SecretKey} for Encryption using AES algorithm
     * This should only run once like during fresh sign up or sign in
     *
     * @return {@link SecretKey} used for encryption
     * @throws NoSuchAlgorithmException is not supported on the platform
     */
    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        // Generate a 256 bit key
        final int keyLength = 256;
        SecureRandom secureRandom = new SecureRandom();

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keyLength, secureRandom);
        return keyGenerator.generateKey();

    }

    /**
     * Used to create a {@link KeyStore} jks file for our app. This is done on fresh login
     *
     * @param context  App context
     * @param password is the user supplied password. Can make use of the validated password the user supplies at sign in
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    private static void createKeystore(Context context, String password) throws CryptoException {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            throw new CryptoException("Failed to get keystore of specified type", e);
        }

        FileInputStream fis = null;
        try {
            fis = new FileInputStream(getKeyStoreFile(context));
            keyStore.load(fis, password.toCharArray());
        } catch (IOException e) {
            throw new CryptoException("Failed to open keystore file!", e);
        } catch (NoSuchAlgorithmException | CertificateException e) {
            throw new CryptoException("Failed to load keystore", e);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    throw new CryptoException("Failed to close keystore file", e);
                }
            }
        }
    }

    private static File getKeyStoreFile(Context context) throws IOException {
        File dirKeyStore = new File(context.getFilesDir(), "keystore");
        dirKeyStore.mkdir();
        File fileKeyStore = new File(dirKeyStore, "my_key_store.js");
        fileKeyStore.createNewFile();
        return fileKeyStore;
    }

    /**
     * Saves the given {@link SecretKey} to our keyStore
     *
     * @param context
     * @param secretKey to be saved
     * @param password  to unlock the keystore
     * @throws IOException
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    public static void saveKeyToKeyStore(Context context, SecretKey secretKey, String alias, String password) throws CryptoException {
        KeyStore.ProtectionParameter protectionParameter =
                new KeyStore.PasswordProtection(password.toCharArray());

        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            throw new CryptoException("Failed to get keystore of specified type", e);
        }

        // Load the key store
        FileInputStream fis = null;
        try {
            //fis = new FileInputStream(getKeyStoreFile(context));
            keyStore.load(null, password.toCharArray());
        } catch (IOException e) {
            throw new CryptoException("Failed to open keystore file!", e);
        } catch (NoSuchAlgorithmException | CertificateException e) {
            throw new CryptoException("Failed to load keystore", e);
        }

        // Save the secrete key under the given alias
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        try {
            keyStore.setEntry(alias, secretKeyEntry, protectionParameter); /* The protection parameter can be null */
        } catch (KeyStoreException e) {
            throw new CryptoException("Failed to set entry!", e);
        }

        // SAve the key store
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(getKeyStoreFile(context));
            keyStore.store(fos, password.toCharArray());
        } catch (IOException e) {
            throw new CryptoException("Failed to open keystore file!", e);
        } catch (NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            throw new CryptoException("Failed to load keystore", e);
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    throw new CryptoException("Failed to close keystore file", e);
                }
            }
        }

    }

    /**
     * Reads the keystore file and retrieves the {@link SecretKey} specified by the given alias
     * and protected by the given password
     *
     * @param context  application context
     * @param alias    is used to identify the entry
     * @param password is used to protect the entry. Can be null
     * @return {@link SecretKey} that we require for our encryption or decryption
     * @throws CryptoException a simple exception handling class
     */
    public static SecretKey getSecretKeyFromKeyStore(Context context, String alias, String password) throws CryptoException {

        KeyStore.ProtectionParameter protectionParameter =
                new KeyStore.PasswordProtection(password.toCharArray());

        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            throw new CryptoException("Failed to get keystore of specified type", e);
        }

        // Load the key store
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(getKeyStoreFile(context));
            keyStore.load(fis, password.toCharArray());
        } catch (IOException e) {
            throw new CryptoException("Failed to open keystore file!", e);
        } catch (NoSuchAlgorithmException | CertificateException e) {
            throw new CryptoException("Failed to load keystore", e);
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    throw new CryptoException("Failed to close keystore file", e);
                }
            }
        }

        // Retrieve the entry using the given alias and protection
        KeyStore.SecretKeyEntry secretKeyEntry;
        try {
            secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, protectionParameter);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            throw new CryptoException("Error getting secret key from keystore!", e);
        }

        if (secretKeyEntry == null) {
            return null;
        }
        return secretKeyEntry.getSecretKey();
    }
}