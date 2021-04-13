package com.xumumi.function;

import javax.servlet.http.HttpServletRequest;

/**
 * 守卫函数接口
 *
 * @author XUMUMI
 * @since 1.9
 */
@FunctionalInterface
public interface GuardCallback {
    /**
     * 执行回调函数
     *
     * @param request 登录请求
     */
    void apply(HttpServletRequest request);
}
