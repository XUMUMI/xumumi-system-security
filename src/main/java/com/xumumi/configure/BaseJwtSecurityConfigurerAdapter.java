package com.xumumi.configure;

import com.xumumi.configure.config.AuthorizeConfig;
import com.xumumi.configure.config.BasicConfig;
import com.xumumi.configure.config.TokenConfig;
import com.xumumi.filter.AbstractJsonAuthenticationFilter;
import com.xumumi.filter.JwtAuthenticationFilter;
import com.xumumi.filter.JwtLoginFilter;
import com.xumumi.filter.impl.JwtAuthenticationFilterImpl;
import com.xumumi.filter.impl.JwtLoginFilterImpl;
import org.apache.commons.lang.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.Map;
import java.util.function.Function;

/**
 * 安全过滤器配置
 * 该类实现了常用功能
 * 可以直接通过继承此类并加上 {@link org.springframework.security.config.annotation.web.configuration.EnableWebSecurity} 来实现最基础的配置
 * 也可以自行改用 {@link AbstractJsonAuthenticationFilter} 和 {@link JwtAuthenticationFilterImpl} 然后自行配置
 *
 * @author XUMUMI
 * @since 1.9
 */
@SuppressWarnings({"SpringJavaAutowiredMembersInspection", "AbstractClassNeverImplemented"})
@ComponentScan("com.xumumi.*")
public abstract class BaseJwtSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
    @Autowired
    private BasicConfig basicConfig;
    @Autowired
    private AuthorizeConfig authorizeConfig;
    @Autowired
    private TokenConfig tokenConfig;

    private JwtLoginFilter loginFilter;
    private JwtAuthenticationFilter authenticationFilter;

    private Function<HttpServletRequest, String> secretCallback;
    private String tokenName;
    private String roleParameter;
    private String loginProcessingUrl;
    private long expireDuration;

    /**
     * 配置过滤器设置方法，继承后通过重写该函数进行配置
     *
     * @param basic     基础配置
     * @param authorize 授权配置
     * @param token     token 配置
     * @see BasicConfig
     * @see AuthorizeConfig
     */
    protected abstract void configure(final BasicConfig basic,
                                      final AuthorizeConfig authorize,
                                      final TokenConfig token);

    /**
     * 配置请求处理方式
     *
     * @param http 用于使用配置 http 信息
     * @throws Exception 重写异常
     */
    @SuppressWarnings("ChainedMethodCall")
    @Override
    protected final void configure(final HttpSecurity http) throws Exception {
        /* 获取配置 */
        configure(basicConfig, authorizeConfig, tokenConfig);
        loginProcessingUrl = basicConfig.getLoginProcessingUrl();
        /* 白名单 */
        String[] permitAll = authorizeConfig.getPermitAll();
        //noinspection SuspiciousArrayCast
        permitAll = (String[]) ArrayUtils.add(permitAll, loginProcessingUrl);
        http.authorizeRequests().antMatchers(permitAll).permitAll();
        /* 需登录 */
        final String[] authentication = authorizeConfig.getAuthentication();
        if (null != authentication) {
            http.authorizeRequests().antMatchers(authentication).authenticated();
        }

        /* 角色权限 */
        final Map<? extends Serializable, ? extends Serializable> roleRightsMap = authorizeConfig.getRoleRightsMap();
        roleRightsMap.forEach((key, value) -> {
            try {
                final Class<? extends Serializable> valueClass = value.getClass(), keyClass = key.getClass();
                http.authorizeRequests()
                        /* 适配字符串和字符串数组 */
                        .antMatchers(String[].class == valueClass ? (String[]) value : new String[]{(String) value})
                        .hasAnyRole(String[].class == keyClass ? (String[]) key : new String[]{(String) key});
            } catch (final Exception ignored) {
            }
        });
        /* 其他 */
        http.authorizeRequests().anyRequest().denyAll();
        /* 配置过滤器 */
        secretCallback = tokenConfig.getSecretCallback();
        tokenName = tokenConfig.getTokenName();
        expireDuration = tokenConfig.getExpireDuration();
        roleParameter = basicConfig.getRoleParameter();
        /* 配置登录过滤器 */
        final AuthenticationManager manager = authenticationManager();
        configureLoginFilter(manager);
        /* 配置请求过滤器 */
        configureAuthenticationFilter();
        /* 写入 */
        http
                /* 登录过滤器 */
                .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class)
                /* 请求过滤器 */
                .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
                /* 无状态身份处理不需要 session */
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        /* 配置拦截器 */
        final CookieCsrfTokenRepository csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        http.csrf()
                /* 拦截跨站请求伪造 */
                .csrfTokenRepository(csrfTokenRepository)
                /* 忽略白名单 */
                .ignoringAntMatchers(permitAll);
    }

    /**
     * 该函数用于配置生成 loginFilter
     * 调用该函数之前必须保证 basicConfig 和 tokenConfig 已经配置，同时 tokenName、roleParameter、loginProcessingUrl 和 secretCallback 不为空
     *
     * @param manager 用于初始化 JwtLoginFilterImpl 的 AuthenticationManager
     */
    @SuppressWarnings("NestedMethodCall")
    private void configureLoginFilter(final AuthenticationManager manager) {
        loginFilter = JwtLoginFilterImpl.createJwtLoginFilter(manager, loginProcessingUrl, secretCallback);
        loginFilter.setSuccessCallback(basicConfig.getSuccessCallback());
        loginFilter.setFailureCallback(basicConfig.getFailureCallback());
        loginFilter.setGuardCallback(basicConfig.getGuardCallback());
        loginFilter.setUsernameParameter(basicConfig.getUsernameParameter());
        loginFilter.setPasswordParameter(basicConfig.getPasswordParameter());
        loginFilter.setCookiesCallback(tokenConfig.getCookiesCallback());
        loginFilter.setTokenName(tokenName);
        loginFilter.setRoleParameter(roleParameter);
        loginFilter.setClaimCallback(tokenConfig.getClaimCallback());
        loginFilter.setRmbParameter(tokenConfig.getRmbParameter());
        loginFilter.setRmbValue(tokenConfig.getRmbValue());
        loginFilter.setRmbExpireTime(tokenConfig.getRmbExpireTime());
        loginFilter.setDefaultExpireTime(tokenConfig.getDefaultExpireTime());
    }

    /**
     * 该函数用于配置生成 authenticationFilter
     */
    private void configureAuthenticationFilter() {
        authenticationFilter = JwtAuthenticationFilterImpl.createJwtAuthenticationFilter(secretCallback);
        authenticationFilter.setTokenName(tokenName);
        authenticationFilter.setRoleParameter(roleParameter);
        authenticationFilter.setExpireDuration(expireDuration);
    }
}

