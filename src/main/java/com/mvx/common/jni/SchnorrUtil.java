package com.mvx.common.jni;


import com.mvx.common.jni.schnorr.KR;
import com.mvx.common.jni.schnorr.SchnorrSig;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

@Slf4j
public class SchnorrUtil {

    public static final ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    public static final ECPoint G = ecSpec.getG();
    public static final BigInteger order = ecSpec.getN();
    public static final BigInteger p = bytesToBigInteger(Hex.decode("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"));


    public static SchnorrSig sign(ECPoint R, ECPoint P, byte[] hash, byte[] privkey) {
//        /* Hash private key & message hash, convert to int mod order */
        BigInteger k = bytesToBigInteger(EncryptionUtil.sHA256(merge(privkey, hash))).mod(order);
//
//        /* Use k value as deterministic nonce for R point */
        ECPoint R1 = G.multiply(k).normalize();

        /* Checks if R is a quadratic residue (?) */
        while (jacobi(R1.getAffineYCoord().toBigInteger()) != 1) {
            k = (order.subtract(k));
            R1 = G.multiply(k).normalize();
        }

        /* Hashes x-coord of R + public key point x coord + message hash, converts to int mod order */
        BigInteger e = bytesToBigInteger(EncryptionUtil.sHA256(merge(bigIntegerToBytes(R.getAffineXCoord().toBigInteger(), 32), point_bytes(P), hash))).mod(order);

        /* Returns R point + (k e*priv) mod order */
        //  s = k + H(m || R || P)*x
        return new SchnorrSig(R, k.add(e.multiply(bytesToBigInteger(privkey))).mod(order), new KR(k, R));
    }

    public static SchnorrSig sign(byte[] privkey, byte[] pubkeybytes, byte[] hash) {
        /* Hash private key & message hash, convert to int mod order */
        BigInteger k = bytesToBigInteger(EncryptionUtil.sHA256(merge(privkey, hash))).mod(order);

        /* Use k value as deterministic nonce for R point */
        ECPoint R = G.multiply(k).normalize();

        /* Checks if R is a quadratic residue (?) */
        while (jacobi(R.getAffineYCoord().toBigInteger()) != 1) {
            //   log.error("sign jacobi 0000 ");
            k = (order.subtract(k));
            R = G.multiply(k).normalize();
        }


        /* Hashes x-coord of R + public key point x coord + message hash, converts to int mod order */

        //    log.error("{}",k);
        //  log.error("pubkeybytes:{}",EncryptionUtil.byteArrToHex(pubkeybytes));
        BigInteger e = bytesToBigInteger(EncryptionUtil.sHA256(merge(bigIntegerToBytes(R.getAffineXCoord().toBigInteger(), 32), pubkeybytes, hash))).mod(order);

        /* Returns R point + (k e*priv) mod order */
        return new SchnorrSig(R, k.add(e.multiply(bytesToBigInteger(privkey))).mod(order), new KR(k, R));
    }

    public static boolean verify(SchnorrSig sig, ECPoint R, ECPoint P, byte[] hash) {
        if (!ecSpec.getCurve().importPoint(R).isValid()) {
            log.error("Failed cuz invalid point");
            // return false;
        }

        if (!(bytesToBigInteger(bigIntegerToBytes(R.getAffineXCoord().toBigInteger(), 32)).compareTo(p) == -1)) {
            log.error("Failed cuz Rx greater than curve modulus");
            //  return false;
        }

        if (!(sig.gets().compareTo(order) == -1)) {
            log.error("Failed cuz s greater than curve order");
            // return false;
        }

        BigInteger e = bytesToBigInteger(EncryptionUtil.sHA256(merge(bigIntegerToBytes(R.getAffineXCoord().toBigInteger(), 32), point_bytes(P), hash))).mod(order);

        //sG = R + H(m || R || P)P
        ECPoint R1 = G.multiply(sig.gets()).normalize().subtract(P.multiply(e).normalize()).normalize();

        if (R1.isInfinity()) {
            log.error("Failed cuz R is point @ Infinity");
            //return false;
        }

        if (jacobi(R1.getAffineYCoord().toBigInteger()) != 1) {
            //    log.error("Failed cuz R jacobi thingy stuff");
            //return false;
        }

        if (R1.getAffineXCoord().toBigInteger().compareTo(R.getAffineXCoord().toBigInteger()) != 0) {
            //  log.error("Failed cuz R doesn't match encoded R");
            return false;
        }

        return true;
    }


    public static boolean verify(SchnorrSig sig, ECPoint PubKey, byte[] hash) {
        if (!ecSpec.getCurve().importPoint(PubKey).isValid()) {
            System.out.println("Failed cuz invalid point");
            return false;
        }

        if (!(bytesToBigInteger(bigIntegerToBytes(sig.getR().getAffineXCoord().toBigInteger(), 32)).compareTo(p) == -1)) {
            System.out.println("Failed cuz Rx greater than curve modulus");
            return false;
        }

        if (!(sig.gets().compareTo(order) == -1)) {
            System.out.println("Failed cuz s greater than curve order");
            return false;
        }

        BigInteger e = bytesToBigInteger(EncryptionUtil.sHA256(merge(bigIntegerToBytes(sig.getR().getAffineXCoord().toBigInteger(), 32), point_bytes(PubKey), hash))).mod(order);

        ECPoint R = G.multiply(sig.gets()).normalize().subtract(PubKey.multiply(e).normalize()).normalize();

        if (R.isInfinity()) {
            System.out.println("Failed cuz R is point @ Infinity");
            return false;
        }

        if (jacobi(R.getAffineYCoord().toBigInteger()) != 1) {
            log.error("Failed cuz R jacobi thingy stuff");
            //  return false;
        }

//        log.error("Failed cuz R doesn't match encoded R");
//        log.error(EncryptionUtil.byteArrToHex(hash));
//        log.error(EncryptionUtil.byteArrToHex(sig.getRBytes()));
//        log.error(EncryptionUtil.byteArrToHex(sig.getsBytes()));
//        log.error(EncryptionUtil.byteArrToHex(SchnorrUtil.bigIntegerToBytes(sig.getKr().getK(),32)));
//        log.error(EncryptionUtil.byteArrToHex(SchnorrUtil.point_bytes(sig.getKr().getR())));

        if (R.getAffineXCoord().toBigInteger().compareTo(sig.getR().getAffineXCoord().toBigInteger()) != 0) {
            log.error("Failed cuz R doesn't match encoded R");

            return false;
        }

        return true;
    }

    public static KR getKR(byte[] privkey, byte[] hash) {
        BigInteger k = bytesToBigInteger(EncryptionUtil.sHA256(merge(privkey, hash))).mod(order);

        /* Use k value as deterministic nonce for R point */
        ECPoint R = G.multiply(k).normalize();

        /* Checks if R is a quadratic residue (?) */
        while (jacobi(R.getAffineYCoord().toBigInteger()) != 1) {
            k = (order.subtract(k));
            R = G.multiply(k).normalize();
        }

        return new KR(k, R);
    }

    public static BigInteger bytesToBigInteger(byte[] bb) {
        return (bb == null || bb.length == 0) ? BigInteger.ZERO : new BigInteger(1,bb);
    }


    public static byte[] bigIntegerToBytes(BigInteger b, int numBytes) {
        if (b == null)
            return null;
        byte[] bytes = new byte[numBytes];
        byte[] biBytes = b.toByteArray();
        if (numBytes == biBytes.length)
            return biBytes;
        int start = (biBytes.length == numBytes + 1) ? 1 : 0;
        int length = Math.min(biBytes.length, numBytes);

        System.arraycopy(biBytes, start, bytes, numBytes - length, length);
        return bytes;
    }


    public static int jacobi(BigInteger x) {
        return IntegerFunctions.jacobi(x, p);
    }

    public static ECPoint liftPoint(byte[] x) throws Exception {
        if (x.length != 33) {
            throw new Exception("Input must be 33 bytes: 1 indicator byte & 32 bytes representing the number.");
        } else {
            return ecSpec.getCurve().decodePoint(x).normalize();
        }
    }

    public static byte[] point_bytes(ECPoint point) {
        BigInteger bigInteger = point.getAffineXCoord().toBigInteger();
        //    log.info("{}", bigInteger);
        // return   bigIntegerToBytes(point.getAffineXCoord().toBigInteger(), 32);
        if (point.getAffineYCoord().toBigInteger().getLowestSetBit() != 0) {
            return merge(Hex.decode("02"), bigIntegerToBytes(point.getAffineXCoord().toBigInteger(), 32));
        } else {
            return merge(Hex.decode("03"), bigIntegerToBytes(point.getAffineXCoord().toBigInteger(), 32));
        }
    }

    public static byte[] merge(byte[]... arrays) {
        int arrCount = 0;
        int count = 0;
        for (byte[] array : arrays) {
            arrCount++;
            count += array.length;
        }

        // Create new array and copy all array contents
        byte[] mergedArray = new byte[count];
        int start = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, mergedArray, start, array.length);
            start += array.length;
        }
        return mergedArray;
    }


}
