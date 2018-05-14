package net.easyappsecurity.account.recovery.util;

import java.security.MessageDigest;

public class CryptoUtil {

    private CryptoUtil() {
    }

    public static byte[] sha256(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(content);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

}
