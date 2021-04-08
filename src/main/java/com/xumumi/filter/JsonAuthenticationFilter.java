package com.xumumi.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.xumumi.util.CookieUtils;
import com.xumumi.util.JwtUtils;
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
import java.util.function.Function;

/**
 * Json 请求过滤器, 继承于 AbstractAuthenticationProcessingFilter
 * 此过滤器的配置使用了链式方法，可参考 {@link com.xumumi.config.BaseJwtSecurityConfigurerAdapter} 进行配置
 *
 * @author XUMUMI
 * @see com.xumumi.config.BaseJwtSecurityConfigurerAdapter
 * @since 1.0
 */
@SuppressWarnings("unused")
public class JsonAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    /**
     * 记住我子类，用于设置记住我功能相关功能
     *
     * @author XUMUMI
     * @since 1.0
     */
    public class RememberMe {
        /* 默认值 */
        private String parameter = "remember";
        private String value = "true";
        private long expireTime = 7 * 24 * 60 * 60 * 1000;

        /**
         * 自定义记住我的字段名，默认值为 "remember"
         *
         * @param parameter 字段名
         * @return 返回记住我对象本身以供链式设置
         */
        public RememberMe parameter(String parameter) {
            this.parameter = Objects.requireNonNullElse(parameter, this.parameter);
            return this;
        }

        /**
         * 自定义当记住我字段的值为和值时为启用记住我功能，默认值为 "true"
         *
         * @param value 字段值
         * @return 返回记住我对象本身以供链式设置
         */
        public RememberMe value(String value) {
            this.value = Objects.requireNonNullElse(value, this.value);
            return this;
        }

        /**
         * 自定义记住我超时时间，默认值为 7 天
         *
         * @param expireTime 超时时长，单位为毫秒
         * @return 返回记住我对象本身以供链式设置
         */
        public RememberMe expireTime(long expireTime) {
            this.expireTime = Objects.requireNonNullElse(expireTime, this.expireTime);
            return this;
        }

        /**
         * 对父类设置链进行粘合，回到主设置链
         *
         * @return 返回过滤器对象本身以供链式设置
         */
        public JsonAuthenticationFilter and() {
            return that();
        }
    }

    /* 字段与变量 */

    private String tokenName = "USER-TOKEN";
    private String usernameParameter = "username";
    private String passwordParameter = "password";
    private final RememberMe rememberMe = new RememberMe();
    private long defaultExpireTime = 5 * 60 * 1000;

    /* 回调函数 */

    private final Function<HttpServletRequest, String> secret;
    private Function<Authentication, Map<String, String>> claim = e -> null;
    private Function<Authentication, List<Cookie>> cookies = null;
    private Result<Authentication> success = null;
    private Result<AuthenticationException> failure = null;
    private Guard guard = null;

    /**
     * 构造器
     *
     * @param authenticationManager 必须传入认证管理器以供使用
     */
    public JsonAuthenticationFilter(@NonNull AuthenticationManager authenticationManager, String loginProcessingUrl
            , Function<HttpServletRequest, String> secret) {
        super(new AntPathRequestMatcher(loginProcessingUrl, HttpMethod.POST.name()), authenticationManager);
        /* 配置密钥 */
        this.secret = secret;
        /* 配置登录成功、失败处理器 */
        this.setAuthenticationSuccessHandler(this::successHandler);
        this.setAuthenticationFailureHandler(this::failureHandler);
    }

    /**
     * 链式调用连接函数，当其他对象设置完毕时可以通过改函数回到当前设置链
     *
     * @return 返回过滤器对象本身以供链式设置
     */
    private JsonAuthenticationFilter that() {
        return this;
    }


    /**
     * 设置与记住我功能相关的信息，设置结束后可以通过 {@link RememberMe#and()} 函数回到当前设置链
     *
     * @return 返回 rememberMe 对象以供设置
     */
    public RememberMe rememberMe() {
        return rememberMe;
    }

    /**
     * 自定义默认超时时长
     *
     * @param defaultExpireTime 自定义 token 默认超时时长，单位为毫秒
     * @return 返回过滤器对象本身以供链式设置
     */
    public JsonAuthenticationFilter defaultExpireTime(long defaultExpireTime) {
        this.defaultExpireTime = Objects.requireNonNullElse(defaultExpireTime, this.defaultExpireTime);
        return this;
    }

    /**
     * 自定义 token 名
     *
     * @param tokenName 自定义 token 的 cookie 名
     * @return 返回过滤器对象本身以供链式设置
     */
    public JsonAuthenticationFilter tokenName(String tokenName) {
        this.tokenName = Objects.requireNonNullElse(tokenName, this.tokenName);
        return this;
    }

    /**
     * 自定义 用户名字段名
     *
     * @param usernameParameter 自定义用户名的字段名
     * @return 返回过滤器对象本身以供链式设置
     */
    public JsonAuthenticationFilter usernameParameter(String usernameParameter) {
        this.usernameParameter = Objects.requireNonNullElse(usernameParameter, this.usernameParameter);
        return this;
    }

    /**
     * 自定义 密码字段名
     *
     * @param passwordParameter 自定义密码的字段名
     * @return 返回过滤器对象本身以供链式设置
     */
    public JsonAuthenticationFilter passwordParameter(String passwordParameter) {
        this.passwordParameter = Objects.requireNonNullElse(passwordParameter, this.passwordParameter);
        return this;
    }

    /**
     * 自定义 token 中存放的额外信息
     *
     * @param claim 返回信息键值对的回调函数
     * @return 返回过滤器对象本身以供链式设置
     */
    public JsonAuthenticationFilter claim(Function<Authentication, Map<String, String>> claim) {
        this.claim = Objects.requireNonNullElse(claim, this.claim);
        return this;
    }

    /**
     * 自定义成功时 cookies 的内容
     *
     * @param cookies 处理 {@link org.springframework.security.core.Authentication} 并返回一个 cookies 列表
     * @return 返回过滤器对象本身以供链式设置
     */
    public JsonAuthenticationFilter cookies(Function<Authentication, List<Cookie>> cookies) {
        this.cookies = cookies;
        return this;
    }

    /**
     * 自定义成功时返回的内容
     *
     * @param success 处理  {@link org.springframework.security.core.Authentication} 并返回一个可序列化对象的回调函数
     * @return 返回过滤器对象本身以供链式设置
     */
    public JsonAuthenticationFilter success(Result<Authentication> success) {
        this.success = success;
        return this;
    }

    /**
     * 自定义失败时返回的内容
     *
     * @param failure 处理  {@link org.springframework.security.core.AuthenticationException} 并返回一个可序列化对象的回调函数
     * @return 返回过滤器对象本身以供链式设置
     */
    public JsonAuthenticationFilter failure(Result<AuthenticationException> failure) {
        this.failure = failure;
        return this;
    }

    /**
     * 自定义守卫拦截方式
     *
     * @param guard 处理 用户标志及 {@link org.springframework.security.core.Authentication}，自行抛出异常
     * @return 返回过滤器对象本身以供链式设置
     */
    public JsonAuthenticationFilter guard(Guard guard) {
        this.guard = guard;
        return this;
    }

    /* 处理器 */

    /**
     * 登录成功处理器：
     * 可以通过 {@link #success(Result)} 函数对返回内容进行修改，
     * 可以用过 {@link #cookies(Function)} 函数对返回 cookies 进行修改，
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
        if (cookies != null) {
            List<Cookie> cookieList = this.cookies.apply(authResult);
            cookieList.forEach(response::addCookie);
        }
        /* 获取是否记住我 */
        String rememberMeStr = request.getParameter(rememberMe.parameter);
        boolean isRememberMe = Objects.equals(rememberMeStr, rememberMe.value);
        /* 根据是否记住我来设置超时时间 */
        long expireTime = isRememberMe ? rememberMe.expireTime : defaultExpireTime;
        /* 设置 token */
        String jwt = JwtUtils.sign(authResult.getName(), claim.apply(authResult), expireTime, secret.apply(request));
        Cookie token = CookieUtils.generateCookie(tokenName, jwt);
        response.addCookie(token);
        /* 使用 json 格式返回信息 */
        //noinspection AliDeprecation,deprecation 由于主流浏览器尚未将 utf8 作为默认，故不得不使用已弃用属性
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        PrintWriter out = response.getWriter();
        ObjectMapper objectMapper = new ObjectMapper();
        /* 判断返回默认信息或自定义信息并写入 */
        Object result = success == null ? authResult : success.apply(request.getRequestURI(), authResult);
        out.write(objectMapper.writeValueAsString(result));
        out.flush();
        out.close();
    }

    /**
     * 登录失败处理器
     * 可以通过 {@link #failure(Result)} 函数对返回内容进行修改, 默认返回认证失败的具体信息
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
        Object result = failure == null ? exception.getMessage() : failure.apply(request.getRequestURI(), exception);
        out.write(objectMapper.writeValueAsString(result));
        out.flush();
        out.close();
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
        if (guard != null) {
            guard.apply(request.getSession().getId(), authRequest);
        }
        /* 验证并返回 */
        return getAuthenticationManager().authenticate(authRequest);
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
        if(body.length > 0) {
            Map<String, String> streamBean = objectMapper.readValue(body, new TypeReference<>() {
            });
            /* 处理从 json 中得到的用户名和密码 */
            username = streamBean.get(usernameParameter);
            username = Objects.requireNonNullElse(username, StringUtils.EMPTY);
            username = username.trim();
            username = HtmlUtils.htmlEscape(username);
            password = streamBean.get(passwordParameter);
            password = Objects.requireNonNullElse(password, StringUtils.EMPTY);
        }
        /* 将其处理为 UsernamePasswordAuthenticationToken 对象 */
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        token.setDetails(request.getParameterMap());
        return token;
    }

    /* 接口 */

    /**
     * 结果处理函数接口
     *
     * @param <Input> 传入类型
     */
    @FunctionalInterface
    public interface Result<Input> {
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
    public interface Guard {
        /**
         * 执行回调函数
         *
         * @param id             用户的唯一标志
         * @param authentication 登录信息
         */
        void apply(String id, Authentication authentication);
    }
}
