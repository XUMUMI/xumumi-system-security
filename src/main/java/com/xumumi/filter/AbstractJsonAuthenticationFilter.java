package com.xumumi.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Json 请求过滤器, 继承于 {@link AbstractAuthenticationProcessingFilter}
 * 此过滤器的配置使用了链式方法，可参考 {@link com.xumumi.config.BaseJwtSecurityConfigurerAdapter} 和 {@link com.xumumi.filter.JwtLoginFilter} 进行配置
 *
 * @author XUMUMI
 * @see com.xumumi.config.BaseJwtSecurityConfigurerAdapter
 * @since 1.9
 */
@SuppressWarnings("unused")
public abstract class AbstractJsonAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    /* 字段 */

    private String usernameParameter = "username";

    /**
     * 获取用户字段名
     *
     * @return 字段名
     */
    public String getUsernameParameter() {
        return usernameParameter;
    }

    /**
     * 修改用户字段名
     *
     * @param usernameParameter 字段名
     */
    public void setUsernameParameter(String usernameParameter) {
        this.usernameParameter = Objects.requireNonNullElse(usernameParameter, this.usernameParameter);
    }

    private String passwordParameter = "password";

    /**
     * 获取密码字段名
     *
     * @return 字段名
     */
    public String getPasswordParameter() {
        return passwordParameter;
    }

    /**
     * 修改密码字段名
     *
     * @param passwordParameter 字段名
     */
    public void setPasswordParameter(String passwordParameter) {
        this.passwordParameter = Objects.requireNonNullElse(passwordParameter, this.passwordParameter);
    }

    /**
     * 构造器
     *
     * @param authenticationManager 必须传入认证管理器以供使用
     * @param loginProcessingUrl    登录请求地址
     */
    public AbstractJsonAuthenticationFilter(@NonNull AuthenticationManager authenticationManager,
                                            @NonNull String loginProcessingUrl) {
        super(new AntPathRequestMatcher(loginProcessingUrl, HttpMethod.POST.name()), authenticationManager);
        /* 配置登录成功、失败处理器 */
        setAuthenticationSuccessHandler(this::successHandler);
        setAuthenticationFailureHandler(this::failureHandler);
    }

    /**
     * 对读取到的请求信息进行处理
     *
     * @param request  接收到的消息
     * @param response 返回的内容
     * @return Authentication 处理完毕的 token
     * @throws IOException 读写异常
     * @see Authentication
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws IOException, AuthenticationException {
        UsernamePasswordAuthenticationToken authRequest;
        /* 从输入流中读取 json */
        authRequest = getAuthRequest(request);
        /* 守卫拦截 */
        guard(request);
        /* 验证并返回 */
        return getAuthenticationManager().authenticate(authRequest);
    }

    /* 处理器 */

    /**
     * 登录成功处理器：
     * 可以通过重写 {@link #successResponse(String, Authentication)} 函数对返回内容进行修改，
     * 可以通过重写 {@link #getCookies(HttpServletRequest, Authentication)} 函数对返回 cookies 进行自定义，
     * 默认返回认证成功的具体信息
     *
     * @param request    传入内容
     * @param response   返回内容
     * @param authResult 验证成功后读取到的详细信息
     * @throws IOException 读写异常
     */
    private void successHandler(HttpServletRequest request, HttpServletResponse response, Authentication authResult)
            throws IOException {
        /* 设置 cookies */
        List<Cookie> cookieList = getCookies(request, authResult);
        cookieList.forEach(response::addCookie);
        /* 使用 json 格式返回信息 */
        //noinspection AliDeprecation,deprecation 由于主流浏览器尚未将 utf8 作为默认，故不得不使用已弃用属性
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        PrintWriter out = response.getWriter();
        ObjectMapper objectMapper = new ObjectMapper();
        /* 判断返回默认信息或自定义信息并写入 */
        Object result = successResponse(request.getRequestURI(), authResult);
        out.write(objectMapper.writeValueAsString(result));
        out.flush();
        out.close();
    }

    /**
     * 登录失败处理器
     * 可以通过重写 {@link #failureResponse(String, AuthenticationException)} 函数对返回内容进行修改, 默认返回认证失败的具体信息
     *
     * @param request   传入内容
     * @param response  返回内容
     * @param exception 验证成功后读取到的详细信息
     * @throws IOException 读写异常
     */
    private void failureHandler(HttpServletRequest request, HttpServletResponse response,
                                AuthenticationException exception) throws IOException {
        /* 使用 json 格式返回信息 */
        //noinspection AliDeprecation,deprecation 由于主流浏览器尚未将 utf8 作为默认，故不得不使用已弃用属性
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        PrintWriter out = response.getWriter();
        ObjectMapper objectMapper = new ObjectMapper();
        /* 判断返回默认信息或自定义信息并写入 */
        Object result = failureResponse(request.getRequestURI(), exception);
        out.write(objectMapper.writeValueAsString(result));
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
    private UsernamePasswordAuthenticationToken getAuthRequest(HttpServletRequest request) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        String username = null, password = null;
        byte[] body = request.getInputStream().readAllBytes();
        if (body.length > 0) {
            Map<String, String> streamBean = objectMapper.readValue(body, new TypeReference<>() {
            });
            /* 处理从 json 中得到的用户名和密码 */
            username = streamBean.get(getUsernameParameter());
            username = Objects.requireNonNullElse(username, StringUtils.EMPTY);
            username = username.trim();
            username = HtmlUtils.htmlEscape(username);
            password = streamBean.get(getPasswordParameter());
            password = Objects.requireNonNullElse(password, StringUtils.EMPTY);
        }
        /* 将其处理为 UsernamePasswordAuthenticationToken 对象 */
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        token.setDetails(request.getParameterMap());
        return token;
    }

    /**
     * 登录成功时调用该函数，可以通过重写自定义返回内容，默认返回认证细节
     *
     * @param url        请求链接
     * @param authResult 认证细节
     * @return 认证细节
     */
    protected Object successResponse(String url, Authentication authResult) {
        return authResult;
    }

    /**
     * 登录失败时调用该函数，可以通过重写自定义返回内容，默认返回错误提示信息
     *
     * @param url       请求链接
     * @param exception 错误详细内容
     * @return 错误提示信息
     */
    protected Object failureResponse(String url, AuthenticationException exception) {
        return exception.getMessage();
    }

    /**
     * 获取登录成功时存入响应头的 cookies 内容，可以为空
     *
     * @param request    请求内容
     * @param authResult 认证细节
     * @return cookies 列表
     */
    protected abstract List<Cookie> getCookies(HttpServletRequest request, Authentication authResult);

    /**
     * 获取登录过程中的守卫，一般可以是验证码或者频繁请求拦截
     *
     * @param request 请求内容
     */
    protected abstract void guard(HttpServletRequest request);
}
