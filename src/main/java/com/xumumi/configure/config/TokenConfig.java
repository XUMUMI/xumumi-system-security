package com.xumumi.configure.config;

import com.xumumi.filter.impl.JwtAuthenticationFilterImpl;
import com.xumumi.filter.impl.JwtLoginFilterImpl;
import com.xumumi.function.CookiesCallback;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.function.Function;

/**
 * Token 设置类接口
 *
 * @author XUMUMI
 * @since 1.9
 */
@SuppressWarnings("unused")
public interface TokenConfig {

    /* 参数 */

    /**
     * 自定义记住我的超时时长，默认为 7 天，最长不可超过 15 天
     *
     * @param time 超时时长，单位毫秒
     * @see JwtLoginFilterImpl#setRmbExpireTime(long)
     */
    void setRmbExpireTime(final long time);

    /**
     * 自定义默认的超时时长，默认为 5 分钟，最长不可超过 15 天
     *
     * @param time 超时时长，单位毫秒
     * @see JwtLoginFilterImpl#setDefaultExpireTime(long)
     */
    void setDefaultExpireTime(final long time);

    /**
     * 自定义记住我为真的值
     *
     * @param value 字段值
     * @see JwtLoginFilterImpl#setRmbValue(String)
     */
    void setRmbValue(final String value);

    /**
     * 自定义刷新 token 时间
     *
     * @param duration 剩余时长
     * @see JwtAuthenticationFilterImpl#setExpireDuration(long)
     */
    void setExpireDuration(long duration);

    /**
     * 获取记住我的超时时长，默认为 7 天
     *
     * @return 超时时长，单位毫秒
     * @see JwtLoginFilterImpl#setRmbExpireTime(long)
     */
    long getRmbExpireTime();

    /**
     * 获取默认的超时时长，默认为 5 分钟
     *
     * @return 超时时长
     * @see JwtLoginFilterImpl#setDefaultExpireTime(long)
     */
    long getDefaultExpireTime();

    /**
     * 获取记住我为真的值
     *
     * @return 字段值
     * @see JwtLoginFilterImpl#setRmbValue(String)
     */
    String getRmbValue();

    /**
     * 获取刷新 token 时间
     *
     * @return 字段名
     * @see JwtAuthenticationFilterImpl#setExpireDuration(long)
     */
    long getExpireDuration();

    /* 字段 */

    /**
     * 自定义记住我字段
     *
     * @param rmbParam 字段名
     * @see JwtLoginFilterImpl#setRmbParameter(String)
     */
    void setRmbParameter(final String rmbParam);

    /**
     * 自定义 token 名
     *
     * @param name token 名的字符串
     * @see JwtLoginFilterImpl#setTokenName(String)
     */
    void setTokenName(final String name);

    /**
     * 获取记住我字段
     *
     * @return 字段名
     * @see JwtLoginFilterImpl#setRmbParameter(String)
     */
    String getRmbParameter();

    /**
     * 获取 token 名
     *
     * @return token 名的字符串
     * @see JwtLoginFilterImpl#setTokenName(String)
     */
    String getTokenName();

    /* 回调 */

    /**
     * 自定义 cookies 回调函数
     *
     * @param callback 处理 {@link Authentication} 并返回一个 cookies 列表
     * @see JwtLoginFilterImpl#setCookiesCallback(CookiesCallback)
     */
    void setCookiesCallback(final CookiesCallback callback);

    /**
     * 自定义 token 附带信息回调函数
     *
     * @param callback 处理 {@link Authentication} 并返回一个 claim 信息列表
     * @see JwtLoginFilterImpl#setClaimCallback(Function)
     */
    void setClaimCallback(final Function<Authentication, Map<String, String>> callback);

    /**
     * 自定义加密密钥
     *
     * @param callback 一个根据用户请求信息 {@link HttpServletRequest} 返回密钥的回调函数
     */
    void setSecretCallback(final Function<HttpServletRequest, String> callback);

    /**
     * 获取 cookies 回调函数
     *
     * @return 回调函数
     * @see JwtLoginFilterImpl#setCookiesCallback(CookiesCallback)
     */
    CookiesCallback getCookiesCallback();

    /**
     * 获取 token 附带信息回调函数
     *
     * @return 回调函数
     * @see JwtLoginFilterImpl#setClaimCallback(Function)
     */
    Function<Authentication, Map<String, String>> getClaimCallback();

    /**
     * 获取加密密钥
     *
     * @return 回调函数
     */
    Function<HttpServletRequest, String> getSecretCallback();
}
