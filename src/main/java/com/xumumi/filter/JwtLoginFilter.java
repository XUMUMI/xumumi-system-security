package com.xumumi.filter;

import com.xumumi.util.CookieUtils;
import com.xumumi.util.JwtUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.util.*;
import java.util.function.Function;


/**
 * Json 请求过滤器, 继承于 {@link AbstractJsonAuthenticationFilter}
 * 此过滤器的配置使用了链式方法，可参考 {@link com.xumumi.config.BaseJwtSecurityConfigurerAdapter} 进行配置
 *
 * @author XUMUMI
 * @see com.xumumi.config.BaseJwtSecurityConfigurerAdapter
 * @since 1.9
 */
@SuppressWarnings("unused")
public class JwtLoginFilter extends AbstractJsonAuthenticationFilter {
    /* token 相关字段及属性 */
    /**
     * 统一 token 名
     */
    private String tokenName = "USER-TOKEN";
    /**
     * 角色字段名
     */
    private String roleParameter = "role";
    /**
     * 记住我字段名
     */
    private String rmbParameter = "remember";
    /**
     * 记住我真值字段名
     */
    private String rmbValue = "true";
    /**
     * 记住我时长
     */
    private long rmbExpireTime = 7 * 24 * 60 * 60 * 1000;
    /**
     * 默认超时时长
     */
    private long defaultExpireTime = 5 * 60 * 1000;

    /* 回调函数 */

    private Function<Authentication, Map<String, String>> claimCallback;
    private final Function<HttpServletRequest, String> secretCallback;
    private ResultCallback<Authentication> successCallback;
    private ResultCallback<AuthenticationException> failureCallback;
    private CookiesCallback cookiesCallback;
    private GuardCallback guardCallback;

    /**
     * 构造器
     *
     * @param authenticationManager 必须传入认证管理器以供使用
     * @param loginProcessingUrl    登录页地址
     * @param secret                加密密钥的回调函数
     */
    public JwtLoginFilter(AuthenticationManager authenticationManager, String loginProcessingUrl,
                          Function<HttpServletRequest, String> secret) {
        super(authenticationManager, loginProcessingUrl);
        /* 配置密钥 */
        secretCallback = secret;
    }

    /**
     * 成功时 cookies 的内容，在此基础上加入 token
     *
     * @param request    登录请求内容
     * @param authResult 认证成功获得的实体信息
     * @return 返回过滤器对象本身以供链式设置
     */
    @Override
    protected final List<Cookie> getCookies(HttpServletRequest request, Authentication authResult){
        /* 得到自定义回调返回值 */
        List<Cookie> cookies = cookiesCallback == null ?
                new ArrayList<>() : cookiesCallback.apply(request, authResult);
        /* 获取是否记住我 */
        String rememberMeStr = request.getParameter(rmbParameter);
        boolean isRememberMe = Objects.equals(rememberMeStr, rmbValue);
        /* 根据是否记住我来设置超时时间 */
        long expireTime = isRememberMe ? rmbExpireTime : defaultExpireTime;
        /* 获取 claim */
        Map<String, String> claim = new HashMap<>(16);
        if(claimCallback != null) {
            claim.putAll(claimCallback.apply(authResult));
        }
        /* 获取角色并存入 claim */
        String role = getRole(authResult.getPrincipal());
        if(role != null) {
            claim.put(roleParameter, role);
        }
        /* 设置 token */
        String jwt = JwtUtils.sign(authResult.getName(), claim, expireTime, secretCallback.apply(request));
        Cookie token = CookieUtils.generateCookie(tokenName, jwt);
        /* 将 token 加入 cookies */
        cookies.add(token);
        return cookies;
    }

    private String getRole(Object principal){
        String role;
        try {
            Field roleField = principal.getClass().getDeclaredField(roleParameter);
            roleField.setAccessible(true);
            role = (String) roleField.get(principal);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            role = null;
        }
        return role;
    }

    /**
     * 守卫内容，调用自定义的回调函数
     *
     * @param request 登录请求内容
     */
    @Override
    protected final void guard(HttpServletRequest request) {
        if (guardCallback != null) {
            guardCallback.apply(request);
        }
    }

    /**
     * 登录成功时返回的内容
     *
     * @param url        请求链接
     * @param authResult 验证信息内容
     * @return 一个可序列化的响应实体
     */
    @Override
    protected final Object successResponse(String url, Authentication authResult) {
        return successCallback != null ? successCallback.apply(url, authResult) : super.successResponse(url, authResult);
    }

    /**
     * 登录成功时返回的内容
     *
     * @param url       请求链接
     * @param exception 错误的详细信息
     * @return 一个可序列化的响应实体
     */
    @Override
    protected final Object failureResponse(String url, AuthenticationException exception) {
        return failureCallback != null ? failureCallback.apply(url, exception) : super.failureResponse(url, exception);
    }

    /* 链式设置函数 */

    /**
     * 自定义用户名字段
     *
     * @param usernameParameter 用户名字段名
     * @return 返回过滤器对象本身以供链式设置
     */
    public JwtLoginFilter usernameParameter(String usernameParameter) {
        setUsernameParameter(usernameParameter);
        return this;
    }

    /**
     * 自定义密码字段
     *
     * @param passwordParameter 密码字段名
     * @return 返回过滤器对象本身以供链式设置
     */

    public JwtLoginFilter passwordParameter(String passwordParameter) {
        setPasswordParameter(passwordParameter);
        return this;
    }

    /**
     * 自定义默认超时时长
     *
     * @param defaultExpireTime 自定义 token 默认超时时长，单位为毫秒
     * @return 返回过滤器对象本身以供链式设置
     */
    public JwtLoginFilter defaultExpireTime(long defaultExpireTime) {
        this.defaultExpireTime = defaultExpireTime == 0 ? this.defaultExpireTime : defaultExpireTime;
        return this;
    }

    /**
     * 自定义成功时 cookies 的内容
     *
     * @param cookies 处理 {@link org.springframework.security.core.Authentication} 并返回一个 cookies 列表
     * @return 返回过滤器对象本身以供链式设置
     */
    public JwtLoginFilter cookiesCallback(CookiesCallback cookies) {
        cookiesCallback = cookies;
        return this;
    }

    /**
     * 自定义成功时返回的内容
     *
     * @param success 处理 {@link org.springframework.security.core.Authentication} 并返回一个可序列化对象的回调函数
     *                该回调函数原型如下 Object success(String path, Authentication authResult)
     *                传入的是调用页面和认证信息，返回一个可序列化的对象
     * @return 返回过滤器对象本身以供链式设置
     * @see ResultCallback
     */
    public JwtLoginFilter success(ResultCallback<Authentication> success) {
        successCallback = success;
        return this;
    }

    /**
     * 自定义失败时返回的内容
     *
     * @param failure 处理  {@link org.springframework.security.core.AuthenticationException} 并返回一个可序列化对象的回调函数
     *                该回调函数原型如下 Object failure(String path, AuthenticationException exception)
     *                传入的是调用页面和错误细节，返回一个可序列化对象
     * @return 返回过滤器对象本身以供链式设置
     * @see ResultCallback
     */
    public JwtLoginFilter failure(ResultCallback<AuthenticationException> failure) {
        failureCallback = failure;
        return this;
    }

    /**
     * 自定义守卫拦截方式，比如验证码，频繁登录拦截等等
     *
     * @param guard 一个回调函数，该回调函数需要接受一个 {@link HttpServletRequest} 并对其进行分析，根据抛出异常以中断登录过程
     * @return 返回过滤器对象本身以供链式设置
     * @see GuardCallback
     */
    public JwtLoginFilter guard(GuardCallback guard) {
        guardCallback = guard;
        return this;
    }

    /**
     * 自定义 token 中存放的额外信息
     *
     * @param claim 返回信息键值对的回调函数
     *              该回调函数需要传入一个包含登录成功后的实体信息 {@link Authentication} 并生成一系列需要存入 token 的额外信息 claim 键值对表并返回
     * @return 返回过滤器对象本身以供链式设置
     */
    public JwtLoginFilter claim(Function<Authentication, Map<String, String>> claim) {
        claimCallback = claim;
        return this;
    }

    /**
     * 自定义 token 名
     *
     * @param tokenName 自定义 token 的 cookie 名
     * @return 返回过滤器对象本身以供链式设置
     */
    public JwtLoginFilter tokenName(String tokenName) {
        this.tokenName = Objects.requireNonNullElse(tokenName, this.tokenName);
        return this;
    }

    /**
     * 自定义记住我的字段名，默认值为 "remember"
     *
     * @param rmbParameter 字段名
     * @return 返回记住我对象本身以供链式设置
     */
    public JwtLoginFilter rmbParameter(String rmbParameter) {
        this.rmbParameter = Objects.requireNonNullElse(rmbParameter, this.rmbParameter);
        return this;
    }

    /**
     * 自定义当记住我字段的值为和值时为启用记住我功能，默认值为 "true"
     *
     * @param rmbValue 字段值
     * @return 返回记住我对象本身以供链式设置
     */
    public JwtLoginFilter rmbValue(String rmbValue) {
        this.rmbValue = Objects.requireNonNullElse(rmbValue, this.rmbValue);
        return this;
    }

    /**
     * 自定义记住我超时时间，默认值为 7 天
     *
     * @param rmbExpireTime 超时时长，单位为毫秒
     * @return 返回记住我对象本身以供链式设置
     */
    public JwtLoginFilter rmbExpireTime(long rmbExpireTime) {
        this.rmbExpireTime = rmbExpireTime == 0 ? this.rmbExpireTime : rmbExpireTime;
        return this;
    }

    /**
     * 自定义角色字段名
     *
     * @param roleParameter 角色字段名
     * @return 返回过滤器本身以供链式设置
     */
    public JwtLoginFilter roleParameter(String roleParameter) {
        this.roleParameter = Objects.requireNonNullElse(roleParameter, this.roleParameter);
        return this;
    }

    /* 接口 */

    /**
     * 结果处理函数接口
     *
     * @param <Input> 传入类型
     */
    @FunctionalInterface
    public interface ResultCallback<Input> {
        /**
         * 执行回调函数
         *
         * @param path   调用路径
         * @param result 执行结果
         * @return 可序列化对象
         */
        Object apply(String path, Input result);
    }

    /**
     * 守卫函数接口
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

    /**
     * 设置 cookies 函数接口
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
}
