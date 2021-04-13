package com.xumumi.function;

import org.springframework.security.core.Authentication;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * 设置 cookies 函数接口
 *
 * @author XUMUMI
 * @since 1.9
 */
@FunctionalInterface
public interface CookiesCallback {
    /**
     * 执行回调函数
     *
     * @param request    登录请求信息
     * @param authResult 认证信息
     * @return 一个添加进响应头的 cookies 列表
     */
    List<Cookie> apply(HttpServletRequest request, Authentication authResult);
}
