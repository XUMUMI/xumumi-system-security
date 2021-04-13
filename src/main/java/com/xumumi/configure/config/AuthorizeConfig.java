package com.xumumi.configure.config;

import java.io.Serializable;
import java.util.Map;

/**
 * 权限设置类接口
 *
 * @author XUMUMI
 * @since 1.9
 */
@SuppressWarnings("unused")
public interface AuthorizeConfig {
    /**
     * 自定义无需授权页面
     *
     * @param rightList 无需授权的页面的地址构成的字符串数组
     */
    void setPermitAll(final String... rightList);

    /**
     * 自定义需要登录后才可以访问的页面
     *
     * @param rightList 地址字符串数组
     */
    void setAuthentication(final String... rightList);

    /**
     * 自定义角色授权的页面，只要有这些角色就可以访问对应的链接
     *
     * @param rolesRightList 一个以角色字符串或字符串数组为键名，地址字符串或字符串数组为键值的表
     */
    void setRoleRightsMap(final Map<? extends Serializable, ? extends Serializable> rolesRightList);

    /**
     * 获取无需授权页面
     *
     * @return 地址列表
     */
    String[] getPermitAll();

    /**
     * 获取登录后才可以访问的页面
     *
     * @return 地址列表
     */
    String[] getAuthentication();

    /**
     * 自定义角色授权的页面，只要有这些角色就可以访问对应的链接
     *
     * @return 一个以角色字符串或字符串数组为键名，地址字符串或字符串数组为键值的表
     */
    Map<? extends Serializable, ? extends Serializable> getRoleRightsMap();
}
