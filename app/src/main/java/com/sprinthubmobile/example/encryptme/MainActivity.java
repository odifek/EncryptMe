package com.sprinthubmobile.example.encryptme;

import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;

import com.sprinthubmobile.example.encryptme.databinding.ActivityMainBinding;

import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.databinding.DataBindingUtil;

public class MainActivity extends AppCompatActivity {
    public static final String TAG = "MainActivity";

    private ActivityMainBinding mBinding;

    private String mPassword;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mBinding = DataBindingUtil.setContentView(this, R.layout.activity_main);


        LayoutInflater inflater = getLayoutInflater();

        View dialogView = inflater.inflate(R.layout.dialog_encrypt_authorize, null);
        AlertDialog alertDialog =
                new AlertDialog.Builder(this)
                        .setView(dialogView)
                        .setPositiveButton("Good", (dialog, which) -> {
                            mPassword = ((EditText) dialogView.findViewById(R.id.edittext_dialog_password)).getText().toString();
                            Log.i(TAG, "onCreate: Taken password");
                            startEncryption(mPassword);
                            dialog.dismiss();
                        })
                        .setNegativeButton("Cancel", (dialog, which) -> {
                            dialog.cancel();
                        })
                        .setTitle("Enter encryption password")
                        .create();

        mBinding.buttonStart.setOnClickListener(v -> alertDialog.show());

        mBinding.buttonDecrypt.setEnabled(false);

        mBinding.buttonDecrypt.setOnClickListener(v -> {
            if (mEncryptedData.length > 0) {
                decryptData(mEncryptedData, mPassword);
            }
        });
    }

    private byte[] mEncryptedData;
    private byte[] mDecryptedData;
    private void startEncryption(String password) {
        // Call this section like only once
        Log.i(TAG, "startEncryption: About to start encryption with password: " + password);
        SecretKey secretKey;
        try {
            secretKey = SecretKeyUtil.generateSecretKey();
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "startEncryption: Failed to generate key!", e);
            return;
        }

        try {
            SecretKeyUtil.saveKeyToKeyStore(this.getApplicationContext(), secretKey, "encryptme", password);
        } catch (CryptoException e) {
            Log.e(TAG, "startEncryption: Unable to save key to key store!", e);
            return;
        }

        // Let's start encrypting our text
        String sourceText = mBinding.edittextOriginal.getText().toString();
        if (!TextUtils.isEmpty(sourceText)) {

            SecretKey mySecretKey;
            try {
                mySecretKey = SecretKeyUtil.getSecretKeyFromKeyStore(this.getApplicationContext(), "encryptme", password);
            } catch (CryptoException e) {
                Log.e(TAG, "startEncryption: Failed to get secret key!", e);
                return;
            }


            try {
                mEncryptedData = CryptoUtil.encrypt(mySecretKey, sourceText.getBytes());
                Log.i(TAG, "startEncryption: Success encrypting data");
                Toast.makeText(this, "Success encrypting data", Toast.LENGTH_SHORT).show();
                Toast.makeText(this, "Press decrypt to start decrypting!", Toast.LENGTH_SHORT).show();
                mBinding.buttonDecrypt.setEnabled(true);
            } catch (CryptoException e) {
                Log.e(TAG, "startEncryption: Failed to encrypt string", e);
            }
        }

    }

    private void decryptData(byte[] data, String password) {

        SecretKey mySecretKey;
        try {
            mySecretKey = SecretKeyUtil.getSecretKeyFromKeyStore(this.getApplicationContext(), "encryptme", password);
        } catch (CryptoException e) {
            Log.e(TAG, "startEncryption: Failed to get secret key!", e);
            return;
        }


        try {
            mDecryptedData = CryptoUtil.decrypt(mySecretKey, data);
            Log.i(TAG, "startEncryption: Success encrypting data");
            Toast.makeText(this, "Success decrypting data", Toast.LENGTH_SHORT).show();

            mBinding.textViewDecrypted.setText(getString(R.string.decrypted_text, new String(mDecryptedData)));
        } catch (CryptoException e) {
            Log.e(TAG, "startEncryption: Failed to encrypt string", e);
        }
    }
}
