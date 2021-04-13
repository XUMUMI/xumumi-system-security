package com.xumumi.filter;

import javax.servlet.Filter;

/**
 * JWT 授权过滤器接口
 *
 * @author XUMUMI
 * @since 1.9
 */
public interface JwtAuthenticationFilter extends Filter {
    /**
     * 自定义令牌名
     *
     * @param name 令牌名
     */
    void setTokenName(final String name);

    /**
     * 自定义角色字段名
     *
     * @param parameter 角色字段名
     */
    void setRoleParameter(final String parameter);
}
