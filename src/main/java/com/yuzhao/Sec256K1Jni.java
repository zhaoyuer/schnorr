package com.yuzhao;

import com.mvx.common.jni.EncryptionUtil;
import com.mvx.common.jni.Secp256k1;
import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @Desc 使用优化后的secp256k1 c库
 * @Author Yu Zhao
 * @Date 2020/12/7 14:18
 * @Version 1.0
 */

@Slf4j
public class Sec256K1Jni {

    public static final BigInteger p = bytesToBigInteger(Hex.decode("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"));

    public static BigInteger bytesToBigInteger(byte[] bb) {
        return (bb == null || bb.length == 0) ? BigInteger.ZERO : new BigInteger(1, bb);
    }

    public static boolean test() {
        // ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1"); // this ec curve is used for bitcoin operations
        try {
            BigInteger x = BigIntegers.createRandomInRange(BigInteger.ONE, p, new SecureRandom());
            ECKey ecKey = ECKey.fromPrivate(x);

            byte[] publicKey = ecKey.getPubKey();
            byte[] privateKey = ecKey.getPrivKeyBytes();

            String test = "TEST";
            byte[] data = test.getBytes();

            //原生签名验签
            return Secp256k1.verify(data, Secp256k1.sign(data, privateKey), publicKey)
                    //数据hash256 hash后签名验签
                    && Secp256k1.verifyECDSASig(publicKey, test, EncryptionUtil.base64Encoder(Secp256k1.applyECDSASig(ecKey.getPrivKey(), test)));
        } catch (Exception e) {
            log.error("", e);
        }

        return false;
    }
}
