package com.xumumi.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xumumi.configure.BaseJwtSecurityConfigurerAdapter;
import com.xumumi.filter.constant.Number;
import com.xumumi.filter.constant.Parameter;
import com.xumumi.filter.impl.JwtLoginFilterImpl;
import com.xumumi.function.CookiesCallback;
import com.xumumi.function.GuardCallback;
import com.xumumi.function.ResultCallback;
import org.apache.commons.lang.StringUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Json 请求过滤器, 继承于 {@link AbstractAuthenticationProcessingFilter}
 * 参考 {@link BaseJwtSecurityConfigurerAdapter} 和 {@link JwtLoginFilterImpl} 进行配置
 *
 * @author XUMUMI
 * @see BaseJwtSecurityConfigurerAdapter
 * @since 1.9
 */
@SuppressWarnings("unused")
public abstract class AbstractJsonAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    /* 字段 */

    private String usernameParameter = Parameter.USER_NAME;
    private String passwordParameter = Parameter.PASSWORD;

    /* 回调 */

    private ResultCallback<? super Authentication> successCallback;
    private ResultCallback<? super AuthenticationException> failureCallback;
    private CookiesCallback cookiesCallback;
    private GuardCallback guardCallback;

    /**
     * 获取用户字段名
     *
     * @return 字段名
     */
    private String getUsernameParameter() {
        return usernameParameter;
    }

    /**
     * 修改用户字段名
     *
     * @param parameter 字段名
     */
    public final void setUsernameParameter(final String parameter) {
        usernameParameter = Objects.requireNonNullElse(parameter, usernameParameter);
    }

    /**
     * 获取密码字段名
     *
     * @return 字段名
     */
    private String getPasswordParameter() {
        return passwordParameter;
    }

    /**
     * 修改密码字段名
     *
     * @param parameter 字段名
     */
    public final void setPasswordParameter(final String parameter) {
        passwordParameter = Objects.requireNonNullElse(parameter, passwordParameter);
    }

    /**
     * 构造器
     *
     * @param manager            必须传入认证管理器以供使用
     * @param loginProcessingUrl 登录请求地址
     */
    protected AbstractJsonAuthenticationFilter(@NonNull final AuthenticationManager manager,
                                               @NonNull final String loginProcessingUrl) {
        //noinspection NestedMethodCall
        super(new AntPathRequestMatcher(loginProcessingUrl, HttpMethod.POST.name()), manager);
    }

    /**
     * 对读取到的请求信息进行处理
     *
     * @param request  接收到的消息
     * @param response 返回的内容
     * @return Authentication 处理完毕的 token
     * @throws AuthenticationException 登录异常
     * @throws IOException             读写异常
     * @see Authentication
     */
    @Override
    public final Authentication attemptAuthentication(final HttpServletRequest request,
                                                      final HttpServletResponse response) throws IOException {
        final UsernamePasswordAuthenticationToken authRequest;
        /* 从输入流中读取 json */
        authRequest = getAuthRequest(request);
        /* 守卫拦截 */
        if (null != guardCallback) {
            guardCallback.apply(request);
        }
        /* 验证并返回 */
        final AuthenticationManager manager = getAuthenticationManager();
        return manager.authenticate(authRequest);
    }

    /* 处理器 */

    /**
     * 重写登录成功逻辑
     *
     * @param request    请求内容
     * @param response   响应内容
     * @param chain      过滤链
     * @param authResult 具体的身份信息
     * @throws IOException 读写异常
     */
    @Override
    protected final void successfulAuthentication(final HttpServletRequest request, final HttpServletResponse response,
                                                  final FilterChain chain, final Authentication authResult)
            throws IOException {
        final SecurityContext context = SecurityContextHolder.getContext();
        context.setAuthentication(authResult);
        if (null != eventPublisher) {
            final Class<? extends AbstractJsonAuthenticationFilter> clazz = getClass();
            eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, clazz));
        }
        successHandler(request, response, authResult);
    }

    /**
     * 自定义成功时返回的内容
     *
     * @param success 处理 {@link org.springframework.security.core.Authentication} 并返回一个可序列化对象的回调函数
     *                该回调函数原型如下 Object success(String path, Authentication authResult)
     *                传入的是调用页面和认证信息，返回一个可序列化的对象
     * @see ResultCallback
     */
    public final void setSuccessCallback(final ResultCallback<? super Authentication> success) {
        successCallback = success;
    }

    /**
     * 登录成功处理器：
     * 可以通过 {@link #setSuccessCallback(ResultCallback)} 传入回调函数对返回内容进行修改，
     * 可以通过重写 {@link #getCookies(HttpServletRequest, Authentication)} 函数对返回 cookies 进行自定义，
     * 默认返回认证成功的具体信息
     *
     * @param request    传入内容
     * @param response   返回内容
     * @param authResult 验证成功后读取到的详细信息
     * @throws IOException 读写异常
     */
    private void successHandler(final HttpServletRequest request, final HttpServletResponse response,
                                final Authentication authResult) throws IOException {
        /* 设置 cookies */
        final List<Cookie> cookieList = getCookies(request, authResult);
        cookieList.forEach(response::addCookie);
        /* 使用 json 格式返回信息 */
        //noinspection AliDeprecation,deprecation 由于主流浏览器尚未将 utf8 作为默认，故不得不使用已弃用属性
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        final PrintWriter out = response.getWriter();
        final ObjectMapper objectMapper = new ObjectMapper();
        /* 判断返回默认信息或自定义信息并写入 */
        final String requestUri = request.getRequestURI();
        final Object result = null != successCallback ? successCallback.apply(requestUri, authResult) : authResult;
        final String message = objectMapper.writeValueAsString(result);
        out.write(message);
        out.flush();
        out.close();
    }

    /**
     * 重写登录失败逻辑
     *
     * @param request  请求内容
     * @param response 响应内容
     * @param failed   错误细节
     * @throws IOException 读写异常
     */
    @Override
    protected final void unsuccessfulAuthentication(final HttpServletRequest request, final HttpServletResponse response,
                                                    final AuthenticationException failed)
            throws IOException {
        SecurityContextHolder.clearContext();
        failureHandler(request, response, failed);
    }

    /**
     * 自定义失败时返回的内容
     *
     * @param failure 处理  {@link org.springframework.security.core.AuthenticationException} 并返回一个可序列化对象的回调函数
     *                该回调函数原型如下 Object failure(String path, AuthenticationException exception)
     *                传入的是调用页面和错误细节，返回一个可序列化对象
     * @see ResultCallback
     */
    public final void setFailureCallback(final ResultCallback<? super AuthenticationException> failure) {
        failureCallback = failure;
    }

    /**
     * 登录失败处理器
     * 可以通过 {@link #setFailureCallback(ResultCallback)} 传入回调函数对返回内容进行修改, 默认返回认证失败的具体信息
     *
     * @param request   传入内容
     * @param response  返回内容
     * @param exception 验证成功后读取到的详细信息
     * @throws IOException 读写异常
     */
    private void failureHandler(final HttpServletRequest request, final HttpServletResponse response,
                                final AuthenticationException exception) throws IOException {
        /* 使用 json 格式返回信息 */
        //noinspection AliDeprecation,deprecation 由于主流浏览器尚未将 utf8 作为默认，故不得不使用已弃用属性
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        final int unauthorized = HttpStatus.UNAUTHORIZED.value();
        response.setStatus(unauthorized);
        final PrintWriter out = response.getWriter();
        final ObjectMapper objectMapper = new ObjectMapper();
        /* 判断返回默认信息或自定义信息并写入 */
        final String requestUri = request.getRequestURI();
        final Object result = null != failureCallback ?
                failureCallback.apply(requestUri, exception) : exception.getMessage();
        final String message = objectMapper.writeValueAsString(result);
        out.write(message);
        out.flush();
        out.close();
    }

    /**
     * 从 json 输入流中读取用户信息并返回令牌
     *
     * @param request 请求内容
     * @return 用户令牌
     * @throws IOException 读写异常
     */
    private UsernamePasswordAuthenticationToken getAuthRequest(final ServletRequest request) throws IOException {
        final ObjectMapper objectMapper = new ObjectMapper();
        String username = null, password = null;
        final ServletInputStream inputStream = request.getInputStream();
        final byte[] body = inputStream.readAllBytes();
        if (0 < body.length) {
            final Map<String, String> streamBean = objectMapper.readValue(body, new MapTypeReference());
            /* 处理从 json 中得到的用户名和密码 */
            username = streamBean.get(usernameParameter);
            username = Objects.requireNonNullElse(username, StringUtils.EMPTY);
            username = username.trim();
            username = HtmlUtils.htmlEscape(username);
            password = streamBean.get(passwordParameter);
            password = Objects.requireNonNullElse(password, StringUtils.EMPTY);
        }
        /* 将其处理为 UsernamePasswordAuthenticationToken 对象 */
        final UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        final Map<String, String[]> parameterMap = request.getParameterMap();
        token.setDetails(parameterMap);
        return token;
    }

    /**
     * 获取登录成功时存入响应头的 cookies 内容，可以为空
     *
     * @param request    请求内容
     * @param authResult 认证细节
     * @return cookies 列表
     */
    @SuppressWarnings("DesignForExtension")
    protected List<Cookie> getCookies(final HttpServletRequest request, final Authentication authResult){
        /* 得到自定义回调返回值 */
        return null == cookiesCallback ? new ArrayList<>(Number.INITIAL_CAPACITY) : cookiesCallback.apply(request, authResult);
    }

    /**
     * 自定义成功时 cookies 的内容
     *
     * @param cookies 处理 {@link org.springframework.security.core.Authentication} 并返回一个 cookies 列表
     */
    public final void setCookiesCallback(final CookiesCallback cookies) {
        cookiesCallback = cookies;
    }

    /**
     * 自定义守卫拦截方式，比如验证码，频繁登录拦截等等
     *
     * @param guard 一个回调函数，该回调函数需要接受一个 {@link HttpServletRequest} 并对其进行分析，根据抛出异常以中断登录过程
     * @see GuardCallback
     */
    public final void setGuardCallback(final GuardCallback guard) {
        guardCallback = guard;
    }

    /**
     * 用于 json 化的 map 类型模板内部类
     */
    private static class MapTypeReference extends TypeReference<Map<String, String>> {
        /**
         * 设定构造器可见性
         */
        MapTypeReference() {
        }
    }
}
