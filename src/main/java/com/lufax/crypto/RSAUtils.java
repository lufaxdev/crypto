package com.lufax.crypto;

import org.apache.commons.lang.ArrayUtils;
import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAUtils {

    static{
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }


    /**
     * 公钥加密
     *
     * @param publicKey
     *            加密的密钥
     * @param raw
     *            明文数据
     * @return 加密后的密文
     * @throws Exception
     */
    public static byte[] encryptWithPublicKey(String publicKey, byte[] raw) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA","BC");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));

        byte[] dataReturn = null;

        for (int offset = 0; offset < raw.length; offset += 100) {
            byte[] b = cipher.doFinal(ArrayUtils.subarray(raw, offset, offset + 100));
            dataReturn = ArrayUtils.addAll(dataReturn, b);
        }
        return dataReturn;
    }

    /**
     * 私钥加密
     *
     * @param privateKey
     *            加密的密钥
     * @param raw
     *            明文数据
     * @return 加密后的密文
     * @throws Exception
     */
    public static byte[] encryptWithPrivateKey(String privateKey, byte[] raw) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA","BC");
        cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey(privateKey));
        byte[] dataReturn = null;

        for (int offset = 0; offset < raw.length; offset += 100) {
            byte[] b = cipher.doFinal(ArrayUtils.subarray(raw, offset, offset + 100));
            dataReturn = ArrayUtils.addAll(dataReturn, b);
        }
        return dataReturn;
    }


    /**
     * 公钥解密
     *
     * @param publicKey
     *            解密的密钥
     * @param raw
     *            已经加密的数据
     * @return 解密后的明文
     * @throws Exception
     */
    public static byte[] decryptWithPublicKey(String publicKey, byte[] raw) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA","BC");
        cipher.init(Cipher.DECRYPT_MODE, getPublicKey(publicKey));
        byte[] dataReturn = null;

        for (int offset = 0; offset < raw.length; offset += 128) {
            byte[] b = cipher.doFinal(ArrayUtils.subarray(raw, offset, offset + 128));
            dataReturn = ArrayUtils.addAll(dataReturn, b);
        }
        return dataReturn;
    }

    /**
     * 私钥解密
     *
     * @param privateKey
     *            解密的密钥
     * @param raw
     *            已经加密的数据
     * @return 解密后的明文
     * @throws Exception
     */
    public static byte[] decryptWithPrivateKey(String privateKey, byte[] raw) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA","BC");
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
        byte[] dataReturn = null;

        for (int offset = 0; offset < raw.length; offset += 128) {
            byte[] b = cipher.doFinal(ArrayUtils.subarray(raw, offset, offset + 128));
            dataReturn = ArrayUtils.addAll(dataReturn, b);
        }
        return dataReturn;
    }

    private static PublicKey getPublicKey(String publicKey) {
        PublicKey pk = null;
        try {
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(new BASE64Decoder().decodeBuffer(publicKey));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            pk = keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return pk;
    }

    private static PrivateKey getPrivateKey(String privateKey) {
        PrivateKey pk = null;
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec;
        try {
            pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(new BASE64Decoder().decodeBuffer(privateKey));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            pk = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return pk;
    }
}
