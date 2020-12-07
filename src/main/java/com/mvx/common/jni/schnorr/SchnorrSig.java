package com.mvx.common.jni.schnorr;


import com.mvx.common.jni.EncryptionUtil;
import com.mvx.common.jni.SchnorrUtil;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

public class SchnorrSig {

    private ECPoint R;
    private BigInteger s;

    private KR kr;

    public KR getKr() {
        return kr;
    }

    public void setKr(KR kr) {
        this.kr = kr;
    }


    public SchnorrSig(ECPoint R, BigInteger s) {
        this.R = R;
        this.s = s;
    }

    public SchnorrSig add(SchnorrSig sig) {
        ECPoint R = this.R.add(sig.getR()).normalize();
        BigInteger S = this.s.add(sig.gets()).mod(SchnorrUtil.order);
        return  new SchnorrSig(R,S);
    }

    public SchnorrSig(ECPoint R, BigInteger s,KR kr) {
        this.R = R;
        this.s = s;
        this.kr = kr;
    }

    public ECPoint getR() {
        return R;
    }

    public byte[] getRBytes() {
        return SchnorrUtil.bigIntegerToBytes(R.getAffineXCoord().toBigInteger(), 32);
    }

    public BigInteger gets() {
        return s;
    }

    public byte[] getsBytes() {
        return SchnorrUtil.bigIntegerToBytes(s, 32);
    }


    @Override
    public String toString() {
        byte[] bytes= SchnorrUtil.merge(getRBytes(),getsBytes());
        return EncryptionUtil.base64Encoder(bytes);
    }



    public SchnorrSig(String str) {
        /* Deserialize signature */
        byte[] data =EncryptionUtil.base64Decoder(str);
        try {
            this.R = SchnorrUtil.liftPoint(Arrays.copyOfRange(data, 0, 32));
            this.s = SchnorrUtil.bytesToBigInteger(Arrays.copyOfRange(data, 32, 64));
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse signature", e);
        }
    }
}
