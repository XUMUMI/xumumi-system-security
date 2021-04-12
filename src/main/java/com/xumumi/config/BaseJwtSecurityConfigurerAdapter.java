package com.xumumi.config;

import com.xumumi.filter.AbstractJsonAuthenticationFilter;
import com.xumumi.filter.JwtAuthenticationFilter;
import com.xumumi.filter.JwtLoginFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * 安全过滤器配置
 * 该类实现了常用功能
 * 可以直接通过继承此类并加上 {@link org.springframework.security.config.annotation.web.configuration.EnableWebSecurity} 来实现最基础的配置
 * 也可以自行改用 {@link AbstractJsonAuthenticationFilter} 和 {@link com.xumumi.filter.JwtAuthenticationFilter} 然后自行配置
 * 如果继承此类后需要自定义细节可以通过实行 {@link #configure(Config)} 进行配置，为了避免冲突，{@link #configure(HttpSecurity)} 不允许被重写
 *
 * @author XUMUMI
 * @since 1.9
 */
public abstract class BaseJwtSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
    /**
     * 用于配置的嵌套设置类
     */
    @SuppressWarnings({"unused", "UnusedReturnValue"})
    protected static class Config {
        /* 路径 */
        private String loginProcessingUrl = "/login";
        /* 字段名 */
        private String usernameParameter;
        private String passwordParameter;
        private String roleParameter;
        /* cookie */
        private String tokenName;
        /* 记住我功能 */
        private String rmbParameter;
        private String rmbValue;
        private long rmbExpireTime;
        private long defaultExpireTime;
        /* 权限 */
        private String[] permitAll;
        private String[] authentication;
        private Map<Serializable, Serializable> roleRightsMap = Map.of();
        /* 回调函数 */
        private JwtLoginFilter.ResultCallback<Authentication> success;
        private JwtLoginFilter.ResultCallback<AuthenticationException> failure;
        private JwtLoginFilter.CookiesCallback cookiesCallback;
        private Function<Authentication, Map<String, String>> claim;
        private JwtLoginFilter.GuardCallback guardCallback;
        private Function<HttpServletRequest, String> secret = e -> e.getSession().getId();

        /* 字段 */

        /**
         * 自定义用户名字段
         *
         * @param usernameParameter 用户名的字段名
         * @return 返回 config 对象本身以供链式设置
         * @see JwtLoginFilter#usernameParameter(String)
         */
        Config usernameParameter(String usernameParameter) {
            this.usernameParameter = usernameParameter;
            return this;
        }

        /**
         * 自定义密码字段
         *
         * @param passwordParameter 密码的字段名
         * @return 返回 config 对象本身以供链式设置
         * @see JwtLoginFilter#passwordParameter(String)
         */
        Config passwordParameter(String passwordParameter) {
            this.passwordParameter = passwordParameter;
            return this;
        }

        /**
         * 自定义角色字段
         *
         * @param roleParameter roleParameter
         * @return 返回 config 对象本身以供链式设置
         * @see JwtAuthenticationFilter#roleParameter(String)
         */
        Config roleParameter(String roleParameter) {
            this.roleParameter = roleParameter;
            return this;
        }


        /**
         * 自定义记住我字段
         *
         * @param rmbParam 字段名
         * @return 返回 config 对象本身以供链式设置
         * @see JwtLoginFilter#rmbParameter(String)
         */
        Config rmbParam(String rmbParam) {
            rmbParameter = rmbParam;
            return this;
        }

        /* 权限 */

        /**
         * 自定义无需授权页面
         *
         * @param permitAll 无需授权的页面的地址构成的字符串数组
         * @return 返回 config 对象本身以供链式设置
         */
        public Config permitAll(String... permitAll) {
            this.permitAll = permitAll;
            return this;
        }

        /**
         * 自定义需要登录后才可以访问的页面
         *
         * @param authentication 地址字符串数组
         * @return 返回 config 对象本身以供链式设置
         */
        Config authentication(String... authentication) {
            this.authentication = authentication;
            return this;
        }

        /**
         * 自定义角色授权的页面，只要有这些角色就可以访问对应的链接
         *
         * @param roleRightsMap 一个以角色字符串或字符串数组为键名，地址字符串或字符串数组为键值的表
         * @return 返回 config 对象本身以供链式设置
         */
        Config roleRightsMap(Map<Serializable, Serializable> roleRightsMap) {
            this.roleRightsMap = roleRightsMap;
            return this;
        }

        /* 回调 */

        /**
         * 自定义登录成功回调函数
         *
         * @param success 处理 {@link org.springframework.security.core.Authentication} 并返回一个可序列化对象的回调函数
         *                该回调函数原型如下 Object success(String path, Authentication authResult)
         *                传入的是调用页面和认证信息，返回一个可序列化的对象
         * @return 返回 config 对象本身以供链式设置
         * @see JwtLoginFilter#success(JwtLoginFilter.ResultCallback)
         */
        Config success(JwtLoginFilter.ResultCallback<Authentication> success) {
            this.success = success;
            return this;
        }

        /**
         * 自定义登录失败回调函数
         *
         * @param failure 处理  {@link org.springframework.security.core.AuthenticationException} 并返回一个可序列化对象的回调函数
         *                该回调函数原型如下 Object failure(String path, AuthenticationException exception)
         *                传入的是调用页面和错误细节，返回一个可序列化对象
         * @return 返回 config 对象本身以供链式设置
         * @see JwtLoginFilter#failure(JwtLoginFilter.ResultCallback)
         */
        Config failure(JwtLoginFilter.ResultCallback<AuthenticationException> failure) {
            this.failure = failure;
            return this;
        }

        /**
         * 自定义 cookies 回调函数
         *
         * @param cookiesCallback 处理 {@link org.springframework.security.core.Authentication} 并返回一个 cookies 列表
         * @return 返回 config 对象本身以供链式设置
         * @see JwtLoginFilter#cookiesCallback(JwtLoginFilter.CookiesCallback)
         */
        Config cookies(JwtLoginFilter.CookiesCallback cookiesCallback) {
            this.cookiesCallback = cookiesCallback;
            return this;
        }

        /**
         * 自定义 token 附带信息回调函数
         *
         * @param claim 处理 {@link org.springframework.security.core.Authentication} 并返回一个 claim 信息列表
         * @return 返回 config 对象本身以供链式设置
         * @see JwtLoginFilter#claim(Function)
         */
        Config claim(Function<Authentication, Map<String, String>> claim) {
            this.claim = claim;
            return this;
        }

        /**
         * 自定义登录守卫回调函数
         *
         * @param guardCallback 处理 用户标志及 {@link org.springframework.security.core.Authentication}，自行抛出异常
         * @return 返回 config 对象本身以供链式设置
         * @see JwtLoginFilter#guard(JwtLoginFilter.GuardCallback)
         */
        Config guard(JwtLoginFilter.GuardCallback guardCallback) {
            this.guardCallback = guardCallback;
            return this;
        }

        /* 杂项 */

        /**
         * 自定义登录页
         *
         * @param loginProcessingUrl 登录页地址
         * @return 返回 config 对象本身以供链式设置
         */
        Config loginProcessingUrl(String loginProcessingUrl) {
            this.loginProcessingUrl = Objects.requireNonNull(loginProcessingUrl);
            return this;
        }

        /**
         * 自定义记住我的超时时长，默认为 7 天，最长不可超过 15 天
         *
         * @param rmbExpireTime 超时时长，单位毫秒
         * @return 返回 config 对象本身以供链式设置
         * @see JwtLoginFilter#rmbExpireTime(long)
         */
        Config rmbExpireTime(long rmbExpireTime) {
            this.rmbExpireTime = rmbExpireTime;
            return this;
        }

        /**
         * 自定义默认的超时时长，默认为 5 分钟，最长不可超过 15 天
         *
         * @param defaultExpireTime 超时时长，单位毫秒
         * @return 返回 config 对象本身以供链式设置
         * @see JwtLoginFilter#defaultExpireTime(long)
         */
        Config defaultExpireTime(long defaultExpireTime) {
            this.defaultExpireTime = defaultExpireTime;
            return this;
        }

        /**
         * 自定义记住我为真的值
         *
         * @param rmbValue 字段值
         * @return 返回 config 对象本身以供链式设置
         * @see JwtLoginFilter#rmbValue(String)
         */
        Config rmbValue(String rmbValue) {
            this.rmbValue = rmbValue;
            return this;
        }

        /**
         * 自定义 token 名
         *
         * @param tokenName token 名的字符串
         * @return 返回 config 对象本身以供链式设置
         * @see JwtLoginFilter#tokenName(String)
         */
        Config tokenName(String tokenName) {
            this.tokenName = tokenName;
            return this;
        }

        /**
         * 自定义加密密钥
         *
         * @param secret 密钥
         * @return 返回 config 对象本身以供链式设置
         */
        Config secret(Function<HttpServletRequest, String> secret) {
            this.secret = Objects.requireNonNullElse(secret, this.secret);
            return this;
        }
    }

    /**
     * 配置 jwt 细节，使用此过滤器时如需自定义配置可通过实现此方法进行自定义配置
     *
     * @param config 设置对象
     */
    protected abstract void configure(Config config);

    /**
     * 配置请求处理方式
     *
     * @param http 用于使用配置 http 信息
     * @throws Exception 重写异常
     */
    @Override
    protected final void configure(HttpSecurity http) throws Exception {
        /* 读取配置 */
        Config config = new Config();
        configure(config);
        /* 配置安全信息 */
        if (config.permitAll != null) {
            /* 白名单 */
            http.authorizeRequests().antMatchers(config.permitAll).permitAll();
        }
        if (config.authentication != null) {
            /* 需登录 */
            http.authorizeRequests().antMatchers(config.authentication).authenticated();
        }
        /* 角色权限 */
        for (Map.Entry<Serializable, Serializable> map : config.roleRightsMap.entrySet()) {
            /* 适配字符串和字符串数组 */
            String[] urls = map.getValue().getClass() == String[].class ?
                    (String[]) map.getValue() : new String[]{(String) map.getValue()};
            String[] roles = map.getKey().getClass() == String[].class ?
                    (String[]) map.getKey() : new String[]{(String) map.getKey()};
            /* 加入配置 */
            http.authorizeRequests().antMatchers(urls).hasAnyRole(roles);
        }
        /* 其他 */
        http.authorizeRequests().anyRequest().authenticated();
        /* 配置过滤器 */
        /* 配置 Json 登录过滤器 */
        JwtLoginFilter jsonFilter =
                new JwtLoginFilter(authenticationManager(), config.loginProcessingUrl, config.secret)
                        /* 回调函数 */
                        .success(config.success).failure(config.failure).guard(config.guardCallback)
                        /* 字段 */
                        .usernameParameter(config.usernameParameter).passwordParameter(config.passwordParameter)
                        .roleParameter(config.roleParameter)
                        /* cookies */
                        .tokenName(config.tokenName).cookiesCallback(config.cookiesCallback).claim(config.claim)
                        .rmbParameter(config.rmbParameter).rmbValue(config.rmbValue)
                        .rmbExpireTime(config.rmbExpireTime).defaultExpireTime(config.defaultExpireTime);
        /* 配置 Jwt 请求过滤器 */
        JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(config.secret)
                .tokenName(config.tokenName).roleParameter(config.roleParameter);
        http
                /* 登录过滤器 */
                .addFilterAt(jsonFilter, UsernamePasswordAuthenticationFilter.class)
                /* 请求过滤器 */
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                /* 无状态身份处理不需要 session */
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        /* 配置拦截器 */
        http.csrf()
                /* 拦截跨站请求伪造 */
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                /* 登录页面不拦截 */
                .ignoringAntMatchers(config.loginProcessingUrl);
        /* 忽略白名单 */
        if (config.permitAll != null) {
            http.csrf().ignoringAntMatchers(config.permitAll);
        }
    }
}
