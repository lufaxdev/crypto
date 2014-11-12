package com.lufax.crypto;

import sun.misc.BASE64Encoder;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class LufaxSecurityUtilsTest {

    public static void main (String[] args) throws NoSuchAlgorithmException {

        KeyPair keyPair = LufaxSecurityUtils.generateRSAKey();
        String publicKey = new BASE64Encoder().encode(keyPair.getPublic().getEncoded());
        String privateKey = new BASE64Encoder().encode(keyPair.getPrivate().getEncoded());

        String originContent = "我是明文啊！！！";

        String sign = LufaxSecurityUtils.sign(privateKey, originContent, "GBK");

        String encryptedContent = LufaxSecurityUtils.encrypt(publicKey, originContent, "GBK");
        String decryptedContent = LufaxSecurityUtils.decrypt(privateKey, encryptedContent, "GBK");

        boolean isSignValid = LufaxSecurityUtils.validateSign(publicKey, decryptedContent, sign, "GBK");

        System.out.println(isSignValid);

    }
}
