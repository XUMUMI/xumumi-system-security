package com.xumumi.filter.impl;

import com.xumumi.configure.BaseJwtSecurityConfigurerAdapter;
import com.xumumi.filter.JwtAuthenticationFilter;
import com.xumumi.filter.constant.Number;
import com.xumumi.filter.constant.Parameter;
import com.xumumi.filter.constant.Path;
import com.xumumi.util.CookieUtils;
import com.xumumi.util.JwtUtils;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

/**
 * JWT 请求过滤器, 继承于 OncePerRequestFilter
 * 可参考 {@link BaseJwtSecurityConfigurerAdapter} 进行配置
 *
 * @author XUMUMI
 * @see BaseJwtSecurityConfigurerAdapter
 * @since 1.9
 */
public final class JwtAuthenticationFilterImpl extends OncePerRequestFilter implements JwtAuthenticationFilter {
    /**
     * 统一 token 名
     */
    private String tokenName = Parameter.TOKEN_NAME;
    /**
     * 角色字段名
     */
    private String roleParameter = Parameter.ROLE;
    /**
     * 生成密钥回调函数
     */
    private final Function<? super HttpServletRequest, String> secretCallback;
    /**
     * 即将过期时间，Token 有效期小于该时长时刷新
     */
    private long expireDuration = Number.ONE_MINUTES_MILLISECONDS;

    /**
     * 构造函数
     *
     * @param secret 密钥构造函数，不允许为 null，函数返回值必须为一个非 null 的 String，建议长度至少为 256 个字符
     */
    private JwtAuthenticationFilterImpl(@NonNull final Function<? super HttpServletRequest, String> secret) {
        secretCallback = secret;
    }

    /**
     * {@link JwtAuthenticationFilter} 生成器
     *
     * @param secret 用于生成密钥的回调函数
     * @return {@link JwtAuthenticationFilter} 对象
     */
    public static JwtAuthenticationFilter createJwtAuthenticationFilter(
            @NonNull final Function<? super HttpServletRequest, String> secret) {
        return new JwtAuthenticationFilterImpl(secret);
    }

    /**
     * 执行验证
     *
     * @param httpServletRequest  请求
     * @param httpServletResponse 响应
     * @param filterChain         过滤链
     * @throws ServletException Servlet 异常
     * @throws IOException      读写异常
     */
    @Override
    protected void doFilterInternal(@NonNull final HttpServletRequest httpServletRequest,
                                    @NonNull final HttpServletResponse httpServletResponse,
                                    final FilterChain filterChain)
            throws ServletException, IOException {
        final Cookie cookie = WebUtils.getCookie(httpServletRequest, tokenName);
        final String token = null != cookie ? cookie.getValue() : null;
        final String secret = secretCallback.apply(httpServletRequest);
        /* 对用 token 获取到的用户进行校验 */
        final Authentication authentication = getAuthentication(token, httpServletRequest);
        final SecurityContext context = SecurityContextHolder.getContext();
        context.setAuthentication(authentication);
        /* 刷新 token */
        final String jwt = JwtUtils.refresh(token, expireDuration, secret);
        if (Objects.nonNull(jwt)) {
            final Cookie newToken = CookieUtils.generateCookie(tokenName, jwt, Path.ROOT, (int) expireDuration);
            httpServletResponse.addCookie(newToken);
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    /**
     * 自定义令牌名
     *
     * @param name 令牌名
     */
    @Override
    public void setTokenName(final String name) {
        tokenName = Objects.requireNonNullElse(name, tokenName);
    }

    /**
     * 自定义角色字段名
     *
     * @param parameter 角色字段名
     */
    @Override
    public void setRoleParameter(final String parameter) {
        roleParameter = Objects.requireNonNullElse(parameter, roleParameter);
    }

    /**
     * 自定义刷新 token 时间
     *
     * @param duration 剩余时长
     */
    @Override
    public void setExpireDuration(final long duration) {
        expireDuration = 0L == duration ? expireDuration : duration;
    }

    /**
     * 从 token 中获取用户信息
     *
     * @param token 用户令牌
     * @return 用户认证信息
     */
    private Authentication getAuthentication(final String token, final HttpServletRequest request) {
        UsernamePasswordAuthenticationToken upToken = null;
        final String secret = secretCallback.apply(request);
        /* 校验 token */
        if (null != token && JwtUtils.isValid(token, secret)) {
            /* 获取用户名 */
            final String username = JwtUtils.getSubject(token);
            /* 获取角色 */
            final String role = JwtUtils.getClaimValue(token, secret, roleParameter);
            final List<SimpleGrantedAuthority> authorities = StringUtils.isEmpty(role) ?
                    new ArrayList<>(Number.INITIAL_CAPACITY) : List.of(new SimpleGrantedAuthority(role));
            /* 获取认证信息 */
            upToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
            upToken.setDetails(authorities);
        }
        return upToken;
    }
}
