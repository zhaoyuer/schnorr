package com.mvx.common.jni;


import org.apache.commons.lang3.StringUtils;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class EncryptionUtil {
    private static final Logger log = LoggerFactory.getLogger(EncryptionUtil.class);


    //base64 加解密
    private static final Base64.Decoder decoder = Base64.getDecoder();
    private static final Base64.Encoder encoder = Base64.getEncoder();

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }










    // 使用 Arrays.copyOf() 方法,但要在 java6++版本中
    public static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }



    // 应用sha256算法让一个输入转变成256位的hash值
    public static String applySha256(String input) {
        try {
            return byte2Hex(sHA256(input));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // 应用sha256算法让一个输入转变成256位的hash值
    public static String applySha256(byte[] input) {
        try {
            return byte2Hex(sHA256(input));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    // 应用ECDSA签名并产生字符数组
    public static String applyECDSASig(String privateKey, String input) {
        try {
            ECKey ecKey = ECKey.fromPrivate(base64Decoder(privateKey));
            return base64Encoder(!Secp256k1.enabled ? ecKey.sign(Sha256Hash.of(input.getBytes())).encodeToDER()
                    : Secp256k1.applyECDSASig(ecKey.getPrivKey(), input));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }



    // 应用ECDSA验证数字签名
    public static boolean verifyECDSASig(String publicKey, String data, String signature) {
        try {
            ECKey ecKey = ECKey.fromPublicOnly(EncryptionUtil.base64Decoder(publicKey));
            //测试 20200713
//            boolean re= Secp256k1.enabled ? Secp256k1.verifyECDSASig(ecKey.getPubKey(), data, signature) :
//                    ecKey.verify(Sha256Hash.of(data.getBytes()).getBytes(), base64Decoder(signature));
//           return re;
            return Secp256k1.enabled ? Secp256k1.verifyECDSASig(ecKey.getPubKey(), data, signature) :
                    ecKey.verify(Sha256Hash.of(data.getBytes()).getBytes(), base64Decoder(signature));

        } catch (Exception e) {
            log.error("应用ECDSA验证数字签名", e);
            return false;
        }
    }



    public static String base64Encoder(byte[] bytes) {
        return encoder.encodeToString(bytes);
    }

    public static byte[] base64Decoder(String str) {
        return decoder.decode(str);
    }


    /**
     * 获取MerkleRoot
     *
     * @param list TransactionId List
     * @return Root
     */
    public static String getRoot(List<String> list) {
        if (list.isEmpty()) return "";
        if (list.size() == 1) return list.get(0);

        int index = 0;
        List<String> list1 = new ArrayList<>();
        while (index < list.size()) {
            String left = list.get(index);
            index++;
            //保证个数为奇数时也可以俩俩hash
            String right = index == list.size() ? left : list.get(index);
            list1.add(applySha256(left + right));
            index++;
        }
        return getRoot(list1);
    }

    /**
     * 获取私钥
     *
     * @param privateKey 私钥字符串
     * @return
     */
    public static PrivateKey getPrivateKey(String privateKey) {
        try {
            KeyFactory keyFactory = null;
            keyFactory = KeyFactory.getInstance("ECDSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoder.decode(privateKey));
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            log.info("私钥字符串转私钥失败", e);
        }

        return null;
    }


    /**
     * 获取公钥
     *
     * @param publicKey 公钥字符串
     * @return
     */
    public static PublicKey getPublicKey(String publicKey) {
        try {
            if (StringUtils.isBlank(publicKey)) {
                return null;
            }
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoder.decode(publicKey));
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            log.info("公钥字符串转公钥失败", e);
        }
        return null;
    }


    //生成SHA256 hash
    public static byte[] sHA256(String str) {
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.getBytes("UTF-8"));
            return messageDigest.digest();
        } catch (Exception e) {
            log.error("获取SHA256哈希出错", e);
        }
        return null;
    }

    //生成SHA256 hash
    public static byte[] sHA256(byte[] bytes) {
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(bytes);
            return messageDigest.digest();
        } catch (Exception e) {
            log.error("获取SHA256哈希出错", e);
        }
        return null;
    }

    public static String byte2Hex(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        String temp = null;
        for (int i = 0; i < bytes.length; i++) {
            temp = Integer.toHexString(bytes[i] & 0xFF);
            if (temp.length() == 1) {
                // 1得到一位的进行补0操作
                stringBuilder.append("0");
            }
            stringBuilder.append(temp);
        }
        return stringBuilder.toString();
    }


    //生成ripemd160 hash
    public static byte[] ripemd160(byte[] bytes) {
        Digest digest = new RIPEMD160Digest();
        digest.update(bytes, 0, bytes.length);
        byte[] rsData = new byte[digest.getDigestSize()];
        digest.doFinal(rsData, 0);
        return rsData;
    }

    // Bsae58 编码表
    private static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final char ENCODED_ZERO = ALPHABET[0];

    // Base58 编码
    public static String base58Encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }
        // 统计前导0
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) {
            ++zeros;
        }
        // 复制一份进行修改
        input = Arrays.copyOf(input, input.length);
        // 最大编码数据长度
        char[] encoded = new char[input.length * 2];
        int outputStart = encoded.length;
        // Base58编码正式开始
        for (int inputStart = zeros; inputStart < input.length; ) {
            encoded[--outputStart] = ALPHABET[divmod(input, inputStart, 256, 58)];
            if (input[inputStart] == 0) {
                ++inputStart;
            }
        }
        // 输出结果中有0,去掉输出结果的前端0
        while (outputStart < encoded.length && encoded[outputStart] == ENCODED_ZERO) {
            ++outputStart;
        }
        // 处理前导0
        while (--zeros >= 0) {
            encoded[--outputStart] = ENCODED_ZERO;
        }
        // 返回Base58
        return new String(encoded, outputStart, encoded.length - outputStart);
    }

    // 进制转换代码
    private static byte divmod(byte[] number, int firstDigit, int base, int divisor) {
        int remainder = 0;
        for (int i = firstDigit; i < number.length; i++) {
            int digit = (int) number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return (byte) remainder;
    }

    private static final char HexCharArr[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    private static final String HexStr = "0123456789abcdef";

    public static String byteArrToHex(byte[] btArr) {
        char strArr[] = new char[btArr.length * 2];
        int i = 0;
        for (byte bt : btArr) {
            strArr[i++] = HexCharArr[bt>>>4 & 0xf];
            strArr[i++] = HexCharArr[bt & 0xf];
        }
        return new String(strArr);
    }

    public static byte[] hexToByteArr(String hexStr) {
        char[] charArr = hexStr.toCharArray();
        byte btArr[] = new byte[charArr.length / 2];
        int index = 0;
        for (int i = 0; i < charArr.length; i++) {
            int highBit = HexStr.indexOf(charArr[i]);
            int lowBit = HexStr.indexOf(charArr[++i]);
            btArr[index] = (byte) (highBit << 4 | lowBit);
            index++;
        }
        return btArr;
    }


    //16进制字符串转字节码
    private static byte charToByte(char c) {
        return (byte) "0123456789abcdef".indexOf(c);
    }

    public static byte[] hexString2Bytes(String hex) {
        if ((hex == null) || (hex.equals(""))) {
            return null;
        } else if (hex.length() % 2 != 0) {
            return null;
        } else {
            hex = hex.toUpperCase();
            int len = hex.length() / 2;
            byte[] b = new byte[len];
            char[] hc = hex.toCharArray();
            for (int i = 0; i < len; i++) {
                int p = 2 * i;
                b[i] = (byte) (charToByte(hc[p]) << 4 | charToByte(hc[p + 1]));
            }
            return b;
        }
    }





}

