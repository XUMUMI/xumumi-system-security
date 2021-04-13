package com.xumumi.configure.config.impl;

import com.xumumi.configure.config.AuthorizeConfig;
import com.xumumi.filter.constant.Number;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * 权限设置类实现
 *
 * @author XUMUMI
 * @since 1.9
 */
@SuppressWarnings("unused")
@Component
final class AuthorizeConfigImpl implements AuthorizeConfig {
    private static final String[] STRINGS = new String[0];
    private String[] permitAll = STRINGS;
    private String[] authentication = STRINGS;
    private final Map<Serializable, Serializable> roleRightsMap = new HashMap<>(Number.INITIAL_CAPACITY);

    /**
     * 自定义无需授权页面
     *
     * @param rightList 无需授权的页面的地址构成的字符串数组
     */
    @Override
    public void setPermitAll(final String... rightList) {
        permitAll = rightList.clone();
    }

    /**
     * 自定义需要登录后才可以访问的页面
     *
     * @param rightList 地址字符串数组
     */
    @Override
    public void setAuthentication(final String... rightList) {
        authentication = rightList.clone();
    }

    /**
     * 自定义角色授权的页面，只要有这些角色就可以访问对应的链接
     *
     * @param rolesRightList 一个以角色字符串或字符串数组为键名，地址字符串或字符串数组为键值的表
     */
    @Override
    public void setRoleRightsMap(final Map<? extends Serializable, ? extends Serializable> rolesRightList) {
        roleRightsMap.putAll(rolesRightList);
    }

    /**
     * 获取无需授权页面
     *
     * @return 无需授权地址列表
     */
    @Override
    public String[] getPermitAll() {
        return permitAll.clone();
    }

    /**
     * 获取登录后才可以访问的页面
     *
     * @return 地址列表
     */
    @Override
    public String[] getAuthentication() {
        return authentication.clone();
    }

    /**
     * 自定义角色授权的页面，只要有这些角色就可以访问对应的链接
     *
     * @return 一个以角色字符串或字符串数组为键名，地址字符串或字符串数组为键值的表
     */
    @Override
    public Map<? extends Serializable, ? extends Serializable> getRoleRightsMap() {
        return Collections.unmodifiableMap(roleRightsMap);
    }
}
