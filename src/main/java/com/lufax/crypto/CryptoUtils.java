package com.lufax.crypto;

import java.security.MessageDigest;

public class CryptoUtils {


    private static final String KEY_MD5 = "MD5";
    private static final String KEY_SHA_256 = "SHA-256";

    public static byte[] encryptSHA256(byte[] data) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance(KEY_SHA_256);
        sha256.update(data);
        return sha256.digest();
    }
}
