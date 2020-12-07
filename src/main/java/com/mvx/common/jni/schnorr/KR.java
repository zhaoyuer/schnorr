package com.mvx.common.jni.schnorr;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class KR {

    private BigInteger k;

    /* Use k value as deterministic nonce for R point */
    private ECPoint R;

    public BigInteger getK() {
        return k;
    }

    public void setK(BigInteger k) {
        this.k = k;
    }

    public ECPoint getR() {
        return R;
    }

    public void setR(ECPoint r) {
        R = r;
    }

    public KR(BigInteger k, ECPoint r) {
        this.k = k;
        R = r;

    }
}
