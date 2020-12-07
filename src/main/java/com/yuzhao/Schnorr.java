package com.yuzhao;

import com.mvx.common.jni.SchnorrUtil;
import com.mvx.common.jni.schnorr.KR;
import com.mvx.common.jni.schnorr.SchnorrSig;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @Desc
 * @Author Yu Zhao
 * @Date 2020/12/7 14:49
 * @Version 1.0
 */

@Slf4j
public class Schnorr {

    public static boolean test() {


        byte[] content = "HELLO".getBytes();
        byte[] content2 = "HE2LLO".getBytes();

        BigInteger x = SchnorrUtil.bytesToBigInteger(generateSeed());
        ECPoint pubPoint = SchnorrUtil.G.multiply(x).normalize();
        byte[] pubkeyBytes = SchnorrUtil.point_bytes(pubPoint);
        byte[] privkeyBytes = SchnorrUtil.bigIntegerToBytes(x, 32);

        SchnorrSig schnorrSig2 = SchnorrUtil.sign(privkeyBytes, pubkeyBytes, content);


        log.info("单签名验签结果:"+SchnorrUtil.verify(schnorrSig2, pubPoint, content));


        x = SchnorrUtil.bytesToBigInteger(generateSeed());

        ECPoint pubPoint2 = SchnorrUtil.G.multiply(x).normalize();
        byte[] pubkeyBytes2 = SchnorrUtil.point_bytes(pubPoint2);
        byte[] privkeyBytes2 = SchnorrUtil.bigIntegerToBytes(x, 32);
        SchnorrSig schnorrSig3 = SchnorrUtil.sign(privkeyBytes2, pubkeyBytes2, content);


        log.info("单签名验签结果:"+SchnorrUtil.verify(schnorrSig3, pubPoint2, content));


        KR kr = SchnorrUtil.getKR(privkeyBytes, content);
        KR kr2 = SchnorrUtil.getKR(privkeyBytes2, content);


        ECPoint R = kr.getR().add(kr2.getR()).normalize();

        ECPoint P = pubPoint.add(pubPoint2).normalize();

        SchnorrSig schnorrSig5 = SchnorrUtil.sign(R, P, content, privkeyBytes);
        SchnorrSig schnorrSig6 = SchnorrUtil.sign(R, P, content, privkeyBytes2);
        SchnorrSig schnorrSig7 = SchnorrUtil.sign(R, P, content2, privkeyBytes2);


        SchnorrSig mul = schnorrSig5.add(schnorrSig6);
        SchnorrSig mul2 = schnorrSig5.add(schnorrSig7);


        log.info("多重签名延签结果:" + SchnorrUtil.verify(mul, R, P, content));
        log.info("多重签名延签结果:" + SchnorrUtil.verify(mul2, R, P, content));



        return SchnorrUtil.verify(schnorrSig2, pubPoint, content)
                &&SchnorrUtil.verify(schnorrSig3, pubPoint2, content)
                &&SchnorrUtil.verify(mul, R, P, content)
                &&!SchnorrUtil.verify(mul2, R, P, content);

    }

    public static byte[] generateSeed() {
        BigInteger x = BigIntegers.createRandomInRange(BigInteger.ONE, SchnorrUtil.p.subtract(BigInteger.ONE), new SecureRandom());
        byte[] result = SchnorrUtil.bigIntegerToBytes(x, 32);
        if (result[0] == -1)
            result[0] = 0;
        return result;

    }
}
