package com.xt.legend.security.shiro.util;

import org.apache.shiro.crypto.hash.SimpleHash;

/**
 * Create User: wangtao
 * Create In 2019-07-09 17:17
 * Description:
 **/
public class CommonUtils {

    public static String securePassword(String password) {
        String s = simpleHash(password).toHex();
        System.out.println(String.format("password after secure: %s", s));
        return s;
    }

    /**
     * 加密类
     *
     * @return
     */
    private static SimpleHash simpleHash(String password) {
        return new SimpleHash("md5", password, "bear", 2);
    }

}
