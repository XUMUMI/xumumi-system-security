package com.xumumi.configure.config;

import com.xumumi.filter.impl.JwtAuthenticationFilterImpl;
import com.xumumi.filter.impl.JwtLoginFilterImpl;
import com.xumumi.function.GuardCallback;
import com.xumumi.function.ResultCallback;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * 基本设置类接口
 *
 * @author XUMUMI
 * @since 1.9
 */
@SuppressWarnings("unused")
public interface BasicConfig {
    /* 参数 */

    /**
     * 自定义登录页
     *
     * @param url 登录页地址
     */
    void setLoginProcessingUrl(final String url);

    /**
     * 获取登录页
     *
     * @return 登录页地址
     */
    String getLoginProcessingUrl();

    /* 字段 */

    /**
     * 自定义用户名字段
     *
     * @param parameter 用户名的字段名
     * @see JwtLoginFilterImpl#setUsernameParameter(String)
     */
    void setUsernameParameter(final String parameter);

    /**
     * 自定义密码字段
     *
     * @param parameter 密码的字段名
     * @see JwtLoginFilterImpl#setPasswordParameter(String)
     */
    void setPasswordParameter(final String parameter);

    /**
     * 自定义角色字段
     *
     * @param parameter 角色字段名
     * @see JwtAuthenticationFilterImpl#setRoleParameter(String)
     */
    void setRoleParameter(final String parameter);

    /**
     * 获取用户名字段
     *
     * @return 字段名
     * @see JwtLoginFilterImpl#setUsernameParameter(String)
     */
    String getUsernameParameter();

    /**
     * 获取密码字段
     *
     * @return 字段名
     * @see JwtLoginFilterImpl#setPasswordParameter(String)
     */
    String getPasswordParameter();

    /**
     * 获取角色字段
     *
     * @return 字段名
     * @see JwtAuthenticationFilterImpl#setRoleParameter(String)
     */
    String getRoleParameter();

    /* 回调 */

    /**
     * 自定义登录成功回调函数
     *
     * @param callback 处理 {@link Authentication} 并返回一个可序列化对象的回调函数
     *                 该回调函数原型如下 Object callback(String path, Authentication authResult)
     *                 传入的是调用页面地址和认证信息，返回一个可序列化的对象
     * @see JwtLoginFilterImpl#setSuccessCallback(ResultCallback)
     */
    void setSuccessCallback(final ResultCallback<Authentication> callback);

    /**
     * 自定义登录失败回调函数
     *
     * @param callback 处理  {@link AuthenticationException} 并返回一个可序列化对象的回调函数
     *                 该回调函数原型如下 Object callback(String path, AuthenticationException exception)
     *                 传入的是调用页面地址和错误细节，返回一个可序列化对象
     * @see JwtLoginFilterImpl#setFailureCallback(ResultCallback)
     */
    void setFailureCallback(final ResultCallback<AuthenticationException> callback);

    /**
     * 自定义登录守卫回调函数
     *
     * @param callback 处理 用户标志及 {@link org.springframework.security.core.Authentication}，自行抛出异常
     *                 该回调函数原型如下 Object callback(Authentication authResult)
     *                 传入的是认证信息，如需拦截则向上抛出异常
     * @see JwtLoginFilterImpl#setGuardCallback(GuardCallback)
     */
    void setGuardCallback(final GuardCallback callback);

    /**
     * 获取登录成功回调函数
     *
     * @return 回调函数
     * @see JwtLoginFilterImpl#setSuccessCallback(ResultCallback)
     */
    ResultCallback<Authentication> getSuccessCallback();

    /**
     * 获取登录失败回调函数
     *
     * @return 回调函数
     * @see JwtLoginFilterImpl#setFailureCallback(ResultCallback)
     */
    ResultCallback<AuthenticationException> getFailureCallback();

    /**
     * 获取登录守卫回调函数
     *
     * @return 回调函数
     */
    GuardCallback getGuardCallback();
}
