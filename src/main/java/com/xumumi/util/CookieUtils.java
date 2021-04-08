package com.xumumi.util;

import javax.servlet.http.Cookie;

/**
 * cookie 生成工具
 * @author XUMUMI
 * @since 1.0
 */
public class CookieUtils {
    /**
     * 生成 cookie
     *
     * @param cookieName cookie 名
     * @param value cookie 内容
     * @param httpOnly cookie 可见性
     * @param uri 可见路径
     * @param expiry 过期时间
     * @return cookie
     */
    public static Cookie generateCookie(String cookieName, String value, boolean httpOnly, String uri, int expiry) {
        Cookie cookie = new Cookie(cookieName, value);
        cookie.setHttpOnly(httpOnly);
        cookie.setPath(uri);
        cookie.setMaxAge(expiry);
        return cookie;
    }
    public static Cookie generateCookie(String cookieName, String value) {
        return generateCookie(cookieName, value, true, "/", 60 * 60 * 24 * 15);
    }
}
