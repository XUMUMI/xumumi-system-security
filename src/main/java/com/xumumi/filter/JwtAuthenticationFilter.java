package com.xumumi.filter;

import com.xumumi.util.JwtUtils;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
 * 此过滤器的配置使用了链式方法，可参考 {@link com.xumumi.config.BaseJwtSecurityConfigurerAdapter} 进行配置
 *
 * @author XUMUMI
 * @see com.xumumi.config.BaseJwtSecurityConfigurerAdapter
 * @since 1.9
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    /**
     * 统一 token 名
     */
    private String tokenName = "USER-TOKEN";
    /**
     * 角色字段名
     */
    private String roleParameter = "role";
    /**
     * 生成密钥回调函数
     */
    private final Function<HttpServletRequest, String> secret;
    /**
     * 构造函数
     * @param secret 密钥构造函数，不允许为 null，函数返回值必须为一个非 null 的 String，建议长度至少为 256 个字符
     */
    public JwtAuthenticationFilter(@NonNull Function<HttpServletRequest, String> secret) {
        this.secret = secret;
    }

    /**
     * 执行验证
     *
     * @param request     请求
     * @param response    响应
     * @param filterChain 过滤链
     * @throws ServletException Servlet 异常
     * @throws IOException      读写异常
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Cookie cookie = WebUtils.getCookie(request, tokenName);
        String token = cookie != null ? cookie.getValue() : null;
        /* 对用 token 获取到的用户进行校验 */
        SecurityContextHolder.getContext().setAuthentication(getAuthentication(token, request));
        filterChain.doFilter(request, response);
    }

    /**
     * 自定义令牌名
     *
     * @param tokenName 令牌名
     * @return 返回过滤器对象本身以供链式设置
     */
    public JwtAuthenticationFilter tokenName(String tokenName) {
        this.tokenName = Objects.requireNonNullElse(tokenName, this.tokenName);
        return this;
    }

    /**
     * 自定义角色字段名
     *
     * @param roleParameter 角色字段名
     * @return 返回过滤器本身以供链式设置
     */
    public JwtAuthenticationFilter roleParameter(String roleParameter) {
        this.roleParameter = Objects.requireNonNullElse(roleParameter, this.roleParameter);
        return this;
    }

    /**
     * 从 token 中获取用户信息
     *
     * @param token 用户令牌
     * @return 用户认证信息
     */
    private Authentication getAuthentication(String token, HttpServletRequest request) {
        String username;
        /* 校验 token */
        if (token != null
                && JwtUtils.verify(token, secret.apply(request))
                && !JwtUtils.isExpired(token)
                && (username = JwtUtils.getSubject(token)) != null) {
            /* 获取角色 */
            String role = JwtUtils.getClaim(token, roleParameter);
            List<GrantedAuthority> authorities = StringUtils.isEmpty(role) ?
                    new ArrayList<>() : new ArrayList<>(List.of(new SimpleGrantedAuthority(role)));
            /* 获取认证信息 */
            UsernamePasswordAuthenticationToken upToken =
                    new UsernamePasswordAuthenticationToken(username, null, authorities);
            upToken.setDetails(authorities);
            return upToken;
        }
        return null;
    }
}
