package com.xumumi.util;

import javax.servlet.http.Cookie;

/**
 * cookie 生成工具
 * @author XUMUMI
 * @since 1.9
 */
public enum CookieUtils {
    /* 工具类 */;

    public static final long MULTIPLE = 1000L;

    /**
     * 生成 cookie
     *
     * @param cookieName cookie 名
     * @param value cookie 内容
     * @param uri 可见路径
     * @param expiry 过期时间
     * @return cookie
     */
    public static Cookie generateCookie(final String cookieName, final String value,
                                        final String uri, final long expiry) {
        final Cookie cookie = new Cookie(cookieName, value);
        cookie.setHttpOnly(true);
        cookie.setPath(uri);
        cookie.setMaxAge((int)(expiry / MULTIPLE));
        return cookie;
    }
}
