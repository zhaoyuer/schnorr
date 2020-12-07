package com.mvx.common.jni;


import com.google.common.base.Preconditions;
import lombok.extern.slf4j.Slf4j;
import org.bitcoin.NativeSecp256k1Util;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Utils;

import java.io.File;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

@Slf4j
public class Secp256k1 {

    public static boolean enabled = false;
    public static final long context;
    private static ThreadLocal<ByteBuffer> nativeECDSABuffer;

    private static native long init_context();

    public static native int ecdsa_verify(ByteBuffer var0, long var1, int var3, int var4);

    public static native byte[][] ecdsa_sign(ByteBuffer var0, long var1);

    public static native int ecdsa_verify2(ByteBuffer var0, int var3, int var4);

    public static native byte[][] ecdsa_sign2(ByteBuffer var0);

    public static synchronized boolean verify(byte[] data, byte[] signature, byte[] pub) {
        Preconditions.checkArgument(data.length == 32 && signature.length <= 520 && pub.length <= 520);
        ByteBuffer byteBuff = (ByteBuffer) nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < 520) {
            byteBuff = ByteBuffer.allocateDirect(520);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }

        byteBuff.rewind();
        byteBuff.put(data);
        byteBuff.put(signature);
        byteBuff.put(pub);
        return ecdsa_verify(byteBuff,context, signature.length, pub.length) == 1;

    }


    // 应用ECDSA验证数字签名
    public static boolean verifyECDSASig(byte[] publicKey, String data, String signature) {
        try {
            return verify(Sha256Hash.of(data.getBytes()).getBytes(), EncryptionUtil.base64Decoder(signature), publicKey);
        } catch (Exception e) {
            log.error("应用ECDSA验证数字签名", e);
            return false;
        }
    }

    public static byte[] applyECDSASig(BigInteger privateKey, String input) {
        try {
            byte[] signature = sign((Sha256Hash.of(input.getBytes()).getBytes()), Utils.bigIntegerToBytes(privateKey, 32));
            return ECKey.ECDSASignature.decodeFromDER(signature).encodeToDER();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public static byte[] sign(byte[] data, byte[] sec) throws NativeSecp256k1Util.AssertFailException {
        Preconditions.checkArgument(data.length == 32 && sec.length <= 32);
        ByteBuffer byteBuff = (ByteBuffer) nativeECDSABuffer.get();
        if (byteBuff == null || byteBuff.capacity() < 64) {
            byteBuff = ByteBuffer.allocateDirect(64);
            byteBuff.order(ByteOrder.nativeOrder());
            nativeECDSABuffer.set(byteBuff);
        }

        byteBuff.rewind();
        byteBuff.put(data);
        byteBuff.put(sec);

        byte[][] retByteArray = ecdsa_sign(byteBuff,context);

        byte[] sigArr = retByteArray[0];
        int sigLen = (new BigInteger(new byte[]{retByteArray[1][0]})).intValue();
        int retVal = (new BigInteger(new byte[]{retByteArray[1][1]})).intValue();
        NativeSecp256k1Util.assertEquals(sigArr.length, sigLen, "Got bad signature length.");
        return retVal == 0 ? new byte[0] : sigArr;
    }




    static {
        boolean isEnabled = true;
        long contextRef = -1L;
        try {

            nativeECDSABuffer = new ThreadLocal();
            System.load(System.getProperty("user.dir")+ File.separator+"libsecp256k1.so");
            contextRef = init_context();
        } catch (Throwable var4) {
            log.error(var4.toString());
            isEnabled = false;
        }
        enabled = isEnabled;
        context = contextRef;
//        enabled=false;

        log.info("enabled:"+enabled);
    }
}
