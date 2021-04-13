package com.xumumi.filter;

import com.xumumi.function.CookiesCallback;
import com.xumumi.function.GuardCallback;
import com.xumumi.function.ResultCallback;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.Filter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * JWT 登录过滤器接口
 *
 * @author XUMUMI
 * @since 1.9
 */
@SuppressWarnings("unused")
public interface JwtLoginFilter extends Filter {
    /* 参数 */

    /**
     * 自定义记住我超时时间
     *
     * @param time 超时时长
     */
    void setRmbExpireTime(final long time);

    /**
     * 自定义默认超时时长
     *
     * @param time 自定义 token 默认超时时长
     */
    void setDefaultExpireTime(final long time);

    /**
     * 自定义当记住我字段的值为和值时为启用记住我功能，默认值为 "true"
     *
     * @param value 字段值
     */
    void setRmbValue(final String value);

    /* 字段 */

    /**
     * 自定义 token 名
     *
     * @param name 自定义 token 的 cookie 名
     */
    void setTokenName(final String name);

    /**
     * 自定义角色字段名
     *
     * @param parameter 角色字段名
     */
    void setRoleParameter(final String parameter);

    /**
     * 自定义记住我的字段名，默认值为 "remember"
     *
     * @param parameter 字段名
     */
    void setRmbParameter(final String parameter);

    /**
     * 修改用户字段名
     *
     * @param parameter 字段名
     */
    void setUsernameParameter(final String parameter);

    /**
     * 修改密码字段名
     *
     * @param parameter 字段名
     */
    void setPasswordParameter(final String parameter);


    /* 回调 */

    /**
     * 自定义 token 中存放的额外信息
     *
     * @param claim 返回信息键值对的回调函数
     *              该回调函数需要传入一个包含登录成功后的实体信息 {@link Authentication} 并生成一系列需要存入 token 的额外信息 claim 键值对表并返回
     */
    void setClaimCallback(final Function<? super Authentication, ? extends Map<String, String>> claim);

    /**
     * 成功时 cookies 的内容，在此基础上加入 token
     *
     * @param request    登录请求内容
     * @param authResult 认证成功获得的实体信息
     * @return cookie 列表
     */
    List<Cookie> getCookies(final HttpServletRequest request, final Authentication authResult);

    /**
     * 自定义成功时返回的内容
     *
     * @param success 处理 {@link org.springframework.security.core.Authentication} 并返回一个可序列化对象的回调函数
     *                该回调函数原型如下 Object success(String path, Authentication authResult)
     *                传入的是调用页面和认证信息，返回一个可序列化的对象
     * @see ResultCallback
     */
    void setSuccessCallback(final ResultCallback<? super Authentication> success);

    /**
     * 自定义失败时返回的内容
     *
     * @param failure 处理  {@link org.springframework.security.core.AuthenticationException} 并返回一个可序列化对象的回调函数
     *                该回调函数原型如下 Object failure(String path, AuthenticationException exception)
     *                传入的是调用页面和错误细节，返回一个可序列化对象
     * @see ResultCallback
     */
    void setFailureCallback(final ResultCallback<? super AuthenticationException> failure);


    /**
     * 自定义成功时 cookies 的内容
     *
     * @param cookies 处理 {@link org.springframework.security.core.Authentication} 并返回一个 cookies 列表
     */
    void setCookiesCallback(final CookiesCallback cookies);

    /**
     * 自定义守卫拦截方式，比如验证码，频繁登录拦截等等
     *
     * @param guard 一个回调函数，该回调函数需要接受一个 {@link HttpServletRequest} 并对其进行分析，根据抛出异常以中断登录过程
     * @see GuardCallback
     */
    void setGuardCallback(final GuardCallback guard);
}
