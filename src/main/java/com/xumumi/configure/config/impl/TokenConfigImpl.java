package com.xumumi.configure.config.impl;

import com.xumumi.configure.config.TokenConfig;
import com.xumumi.filter.impl.JwtAuthenticationFilterImpl;
import com.xumumi.filter.impl.JwtLoginFilterImpl;
import com.xumumi.function.CookiesCallback;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.function.Function;

/**
 * Token 设置类实现
 *
 * @author XUMUMI
 * @since 1.9
 */
@SuppressWarnings("unused")
@Component
final class TokenConfigImpl implements TokenConfig {

    /* 参数 */

    private long rmbExpireTime;
    private long defaultExpireTime;
    private long expireDuration;
    private String rmbValue;

    /* 字段 */

    private String tokenName;
    private String rmbParameter;

    /* 回调函数 */

    private CookiesCallback cookiesCallback;
    private Function<Authentication, Map<String, String>> claimCallback;
    private Function<HttpServletRequest, String> secretCallback = ServletRequest::getRemoteHost;

    /* 参数 */

    /**
     * 自定义记住我的超时时长，默认为 7 天，最长不可超过 15 天
     *
     * @param time 超时时长，单位毫秒
     * @see JwtLoginFilterImpl#setRmbExpireTime(long)
     */
    @Override
    public void setRmbExpireTime(final long time) {
        rmbExpireTime = time;
    }

    /**
     * 自定义默认的超时时长，默认为 5 分钟，最长不可超过 15 天
     *
     * @param time 超时时长，单位毫秒
     * @see JwtLoginFilterImpl#setDefaultExpireTime(long)
     */
    @Override
    public void setDefaultExpireTime(final long time) {
        defaultExpireTime = time;
    }

    /**
     * 自定义记住我为真的值
     *
     * @param value 字段值
     * @see JwtLoginFilterImpl#setRmbValue(String)
     */
    @Override
    public void setRmbValue(final String value) {
        rmbValue = value;
    }

    /**
     * 自定义刷新 token 时间
     *
     * @param duration 剩余时长
     * @see JwtAuthenticationFilterImpl#setExpireDuration(long)
     */
    @Override
    public void setExpireDuration(final long duration) {
        expireDuration = duration;
    }

    /**
     * 获取记住我的超时时长，默认为 7 天
     *
     * @return 超时时长，单位毫秒
     * @see JwtLoginFilterImpl#setRmbExpireTime(long)
     */
    @Override
    public long getRmbExpireTime() {
        return rmbExpireTime;
    }

    /**
     * 获取默认的超时时长，默认为 5 分钟
     *
     * @return 超时时长
     * @see JwtLoginFilterImpl#setDefaultExpireTime(long)
     */
    @Override
    public long getDefaultExpireTime() {
        return defaultExpireTime;
    }

    /**
     * 获取记住我为真的值
     *
     * @return 字段值
     * @see JwtLoginFilterImpl#setRmbValue(String)
     */
    @Override
    public String getRmbValue() {
        return rmbValue;
    }

    /**
     * 获取刷新 token 时间
     *
     * @return 字段名
     * @see JwtAuthenticationFilterImpl#setExpireDuration(long)
     */
    @Override
    public long getExpireDuration() {
        return expireDuration;
    }

    /* 字段 */

    /**
     * 自定义记住我字段
     *
     * @param rmbParam 字段名
     * @see JwtLoginFilterImpl#setRmbParameter(String)
     */
    @Override
    public void setRmbParameter(final String rmbParam) {
        rmbParameter = rmbParam;
    }

    /**
     * 自定义 token 名
     *
     * @param name token 名的字符串
     * @see JwtLoginFilterImpl#setTokenName(String)
     */
    @Override
    public void setTokenName(final String name) {
        tokenName = name;
    }

    /**
     * 获取记住我字段
     *
     * @return 字段名
     * @see JwtLoginFilterImpl#setRmbParameter(String)
     */
    @Override
    public String getRmbParameter() {
        return rmbParameter;
    }

    /**
     * 获取 token 名
     *
     * @return token 名的字符串
     * @see JwtLoginFilterImpl#setTokenName(String)
     */
    @Override
    public String getTokenName() {
        return tokenName;
    }

    /* 回调 */

    /**
     * 自定义 cookies 回调函数
     *
     * @param callback 处理 {@link Authentication} 并返回一个 cookies 列表
     * @see JwtLoginFilterImpl#setCookiesCallback(CookiesCallback)
     */
    @Override
    public void setCookiesCallback(final CookiesCallback callback) {
        cookiesCallback = callback;
    }

    /**
     * 自定义 token 附带信息回调函数
     *
     * @param callback 处理 {@link Authentication} 并返回一个 claim 信息列表
     * @see JwtLoginFilterImpl#setClaimCallback(Function)
     */
    @Override
    public void setClaimCallback(final Function<Authentication, Map<String, String>> callback) {
        claimCallback = callback;
    }

    /**
     * 自定义加密密钥
     *
     * @param callback 一个根据用户请求信息 {@link HttpServletRequest} 返回密钥的回调函数
     */
    @Override
    public void setSecretCallback(final Function<HttpServletRequest, String> callback) {
        secretCallback = callback;
    }

    /**
     * 获取 cookies 回调函数
     *
     * @return 回调函数
     * @see JwtLoginFilterImpl#setCookiesCallback(CookiesCallback)
     */
    @Override
    public CookiesCallback getCookiesCallback() {
        return cookiesCallback;
    }

    /**
     * 获取 token 附带信息回调函数
     *
     * @return 回调函数
     * @see JwtLoginFilterImpl#setClaimCallback(Function)
     */
    @Override
    public Function<Authentication, Map<String, String>> getClaimCallback() {
        return claimCallback;
    }

    /**
     * 获取加密密钥
     *
     * @return 回调函数
     */
    @Override
    public Function<HttpServletRequest, String> getSecretCallback() {
        return secretCallback;
    }
}
