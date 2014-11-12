package com.lufax.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class LufaxSecurityUtils {

    private static Logger log = LoggerFactory.getLogger(LufaxSecurityUtils.class);

    /**
     *
     * 消息签名 1.sha256加密 2.RSA签名 3.base64编码
     *
     * @param privateKey 签名私钥
     * @param src 需要签名的内容
     * @param charset 字符集编码
     *
     * @return 数字签名
     *
     * */
    public static String sign(String privateKey, String src, String charset) {
        try {
            byte[] encrypted = RSAUtils.encryptWithPrivateKey(privateKey, CryptoUtils.encryptSHA256(src.getBytes(charset)));
            return new BASE64Encoder().encode(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }


    /**
     *
     * 消息验签 1.base64解码sign 2.RSA解签sign 3.sha256原文 与解密后的sign 对比
     *
     * @param publicKey 解签公钥
     * @param originContent 消息明文
     * @param sign 签名内容
     * @param charset 字符集编码
     *
     * @return 签名是否一致
     *
     * */
    public static boolean validateSign(String publicKey, String originContent, String sign, String charset) {
        try {
            String originContentSigned = new String(RSAUtils.decryptWithPublicKey(publicKey, new BASE64Decoder().decodeBuffer(sign)));
            String signedToBeValidated = new String(CryptoUtils.encryptSHA256(originContent.getBytes(charset)));
            return signedToBeValidated.equals(originContentSigned);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    /**
     * 消息加密: 1.RSA加密 2.base64编码
     *
     * @param publicKey 加密所使用的公钥
     * @param src 需要加密的内容
     * @param charset 字符集编码
     *
     * @return 加密后的内容
     *
     * */
    public static String encrypt(String publicKey, String src, String charset) {

        try {
            byte[] encrypted = RSAUtils.encryptWithPublicKey(publicKey, src.getBytes(charset));
            return new BASE64Encoder().encode(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    /**
     * 消息加密: 1.base64解码 2.RSA解密
     *
     * @param privateKey 解密所使用的私钥
     * @param src 需要解密的内容
     * @param charset 字符集编码
     *
     * @return 解密后的内容
     *
     * */
    public static String decrypt(String privateKey, String src, String charset) {
        try {
            byte[] encryptedContent = new BASE64Decoder().decodeBuffer(src);
            return new String(RSAUtils.decryptWithPrivateKey(privateKey, encryptedContent), charset);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    
    
    public static KeyPair generateRSAKey () throws NoSuchAlgorithmException {
    	
    	KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		keyPairGen.initialize(1024);
		
		KeyPair keyPair = keyPairGen.generateKeyPair();

        log.info("public key is {}", new BASE64Encoder().encode(keyPair.getPublic().getEncoded()));
        log.info("private key is {}", new BASE64Encoder().encode(keyPair.getPrivate().getEncoded()));

        return keyPair;
    }
}
