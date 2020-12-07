package com.yuzhao;

/**
 * @Desc jdk椭圆曲线签名算法
 * @Author Yu Zhao
 * @Date 2020/12/7 13:14
 * @Version 1.0
 */

import lombok.extern.slf4j.Slf4j;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * 椭圆曲线签名算法，即ECDSA。
 * 　　设私钥、公钥分别为k、K，即K = kG，其中G为G点。
 * <p>
 * 　　私钥签名：
 * 　　1、选择随机数r，计算点rG(x, y)。
 * 　　2、根据随机数r、消息M的哈希h、私钥k，计算s = (h + kx)/r。
 * 　　3、将消息M、和签名{rG, s}发给接收方。
 * <p>
 * 　　公钥验证签名：
 * 　　1、接收方收到消息M、以及签名{rG=(x,y), s}。
 * 　　2、根据消息求哈希h。
 * 　　3、使用发送方公钥K计算：hG/s + xK/s，并与rG比较，如相等即验签成功。
 * <p>
 * 　　原理如下：
 * 　　hG/s + xK/s = hG/s + x(kG)/s = (h+xk)G/s
 * 　　= r(h+xk)G / (h+kx) = rG
 */

@Slf4j
public class Sec256K1Ecc {

    private static final String ALGOR = "SHA256withECDSA";

    public static boolean testA() {
        // ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1"); // this ec curve is used for bitcoin operations
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256k1");
            keyGen.initialize(ecGenParameterSpec, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            byte[] data = "TEST".getBytes();

            return verifySign(data, publicKey, signData(data, privateKey));
        } catch (Exception e) {
            log.error("", e);
        }


        return false;
    }


    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance(ALGOR);
        signer.initSign(key);
        signer.update(data);
        return (signer.sign());
    }

    public static boolean verifySign(byte[] data, PublicKey key, byte[] sig) throws Exception {
        Signature signer = Signature.getInstance(ALGOR);
        signer.initVerify(key);
        signer.update(data);
        return (signer.verify(sig));
    }
}
