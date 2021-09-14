package com.xumumi.configure.config.impl;

import com.xumumi.configure.config.BasicConfig;
import com.xumumi.filter.constant.Path;
import com.xumumi.filter.impl.JwtAuthenticationFilterImpl;
import com.xumumi.filter.impl.JwtLoginFilterImpl;
import com.xumumi.function.GuardCallback;
import com.xumumi.function.ResultCallback;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.Objects;

/**
 * 基础设置类实现
 *
 * @author XUMUMI
 * @since 1.9
 */
@SuppressWarnings("unused")
@Component
final class BasicConfigImpl implements BasicConfig {
    /* 参数 */

    private String loginProcessingUrl = Path.LOGIN;

    /* 字段 */

    private String usernameParameter;
    private String passwordParameter;
    private String roleParameter;

    /* 回调 */

    private ResultCallback<Authentication> successCallback;
    private ResultCallback<AuthenticationException> failureCallback;
    private GuardCallback guardCallback;

    /**
     * 自定义登录页
     *
     * @param url 登录页地址
     */
    @Override
    public void setLoginProcessingUrl(final String url) {
        loginProcessingUrl = Objects.requireNonNullElse(url, loginProcessingUrl);
    }

    /**
     * 获取登录页
     *
     * @return 登录页地址
     */
    @Override
    public String getLoginProcessingUrl() {
        return loginProcessingUrl;
    }

    /* 字段 */

    /**
     * 自定义用户名字段
     *
     * @param parameter 用户名的字段名
     * @see JwtLoginFilterImpl#setUsernameParameter(String)
     */
    @Override
    public void setUsernameParameter(final String parameter) {
        usernameParameter = parameter;
    }

    /**
     * 自定义密码字段
     *
     * @param parameter 密码的字段名
     * @see JwtLoginFilterImpl#setPasswordParameter(String)
     */
    @Override
    public void setPasswordParameter(final String parameter) {
        passwordParameter = parameter;
    }

    /**
     * 自定义角色字段
     *
     * @param parameter 角色字段名
     * @see JwtAuthenticationFilterImpl#setRoleParameter(String)
     */
    @Override
    public void setRoleParameter(final String parameter) {
        roleParameter = parameter;
    }

    /**
     * 获取用户名字段
     *
     * @return 字段名
     * @see JwtLoginFilterImpl#setUsernameParameter(String)
     */
    @Override
    public String getUsernameParameter() {
        return usernameParameter;
    }

    /**
     * 获取密码字段
     *
     * @return 字段名
     * @see JwtLoginFilterImpl#setPasswordParameter(String)
     */
    @Override
    public String getPasswordParameter() {
        return passwordParameter;
    }

    /**
     * 获取角色字段
     *
     * @return 字段名
     * @see JwtAuthenticationFilterImpl#setRoleParameter(String)
     */
    @Override
    public String getRoleParameter() {
        return roleParameter;
    }

    /* 回调 */

    /**
     * 自定义登录成功回调函数
     *
     * @param callback 处理 {@link Authentication} 并返回一个可序列化对象的回调函数
     *                 该回调函数原型如下 Object callback(String path, Authentication authResult)
     *                 传入的是调用页面和认证信息，返回一个可序列化的对象
     * @see JwtLoginFilterImpl#setSuccessCallback(ResultCallback)
     */
    @Override
    public void setSuccessCallback(final ResultCallback<Authentication> callback) {
        successCallback = callback;
    }

    /**
     * 自定义登录失败回调函数
     *
     * @param callback 处理  {@link AuthenticationException} 并返回一个可序列化对象的回调函数
     *                 该回调函数原型如下 Object callback(String path, AuthenticationException exception)
     *                 传入的是调用页面和错误细节，返回一个可序列化对象
     * @see JwtLoginFilterImpl#setFailureCallback(ResultCallback)
     */
    @Override
    public void setFailureCallback(final ResultCallback<AuthenticationException> callback) {
        failureCallback = callback;
    }

    /**
     * 自定义登录守卫回调函数
     *
     * @param callback 处理 用户标志及 {@link org.springframework.security.core.Authentication}，自行抛出异常
     *                 该回调函数原型如下 Object callback(Authentication authResult)
     *                 传入的是认证信息，如需拦截则向上抛出异常
     */
    @Override
    public void setGuardCallback(final GuardCallback callback) {
        guardCallback = callback;
    }

    /**
     * 获取登录成功回调函数
     *
     * @return 回调函数
     * @see JwtLoginFilterImpl#setSuccessCallback(ResultCallback)
     */
    @Override
    public ResultCallback<Authentication> getSuccessCallback() {
        return successCallback;
    }

    /**
     * 获取登录失败回调函数
     *
     * @return 回调函数
     * @see JwtLoginFilterImpl#setFailureCallback(ResultCallback)
     */
    @Override
    public ResultCallback<AuthenticationException> getFailureCallback() {
        return failureCallback;
    }

    /**
     * 获取登录守卫回调函数
     *
     * @return 回调函数
     */
    @Override
    public GuardCallback getGuardCallback() {
        return guardCallback;
    }
}
