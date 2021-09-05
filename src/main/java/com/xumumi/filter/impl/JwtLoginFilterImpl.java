package com.xumumi.filter.impl;

import com.xumumi.configure.BaseJwtSecurityConfigurerAdapter;
import com.xumumi.filter.AbstractJsonAuthenticationFilter;
import com.xumumi.filter.JwtLoginFilter;
import com.xumumi.filter.constant.Number;
import com.xumumi.filter.constant.Parameter;
import com.xumumi.filter.constant.Path;
import com.xumumi.filter.constant.Text;
import com.xumumi.util.CookieUtils;
import com.xumumi.util.JwtUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * Json 请求过滤器, 继承于 {@link AbstractJsonAuthenticationFilter}
 * 此过滤器的配置使用了链式方法，可参考 {@link BaseJwtSecurityConfigurerAdapter} 进行配置
 *
 * @author XUMUMI
 * @see BaseJwtSecurityConfigurerAdapter
 * @since 1.9
 */
@SuppressWarnings("unused")
public final class JwtLoginFilterImpl extends AbstractJsonAuthenticationFilter implements JwtLoginFilter {

    /* 参数 */

    private long rmbExpireTime = Number.SEVEN_DAYS_MILLISECONDS;
    private long defaultExpireTime = Number.FIVE_MINUTES_MILLISECONDS;
    private String rmbValue = Text.TRUE;

    /* 字段 */

    private String tokenName = Parameter.TOKEN_NAME;
    private String roleParameter = Parameter.ROLE;
    private String rmbParameter = Parameter.REMEMBER;

    /* 回调函数 */

    private final Function<? super HttpServletRequest, String> secretCallback;
    private Function<? super Authentication, ? extends Map<String, String>> claimCallback;

    /**
     * 构造器
     *
     * @param manager            必须传入认证管理器以供使用
     * @param loginProcessingUrl 登录页地址
     * @param secret             加密密钥的回调函数
     */
    private JwtLoginFilterImpl(final AuthenticationManager manager, final String loginProcessingUrl,
                               final Function<? super HttpServletRequest, String> secret) {
        super(manager, loginProcessingUrl);
        /* 配置密钥 */
        secretCallback = secret;
    }

    /**
     *{@link JwtLoginFilter} 生成器
     *
     * @param manager            认证管理器
     * @param loginProcessingUrl 登录页地址
     * @param secret             用于生成密钥的回调函数
     * @return {@link JwtLoginFilter} 对象
     */
    public static JwtLoginFilter createJwtLoginFilter(final AuthenticationManager manager, final String loginProcessingUrl,
                                                          final Function<? super HttpServletRequest, String> secret) {
        return new JwtLoginFilterImpl(manager, loginProcessingUrl, secret);
    }

    /* 参数 */

    /**
     * 自定义记住我超时时间，默认值为 7 天
     *
     * @param time 超时时长，单位为毫秒
     */
    @Override
    public void setRmbExpireTime(final long time) {
        if (0L < time) {
            rmbExpireTime = time;
        }
    }

    /**
     * 自定义默认超时时长
     *
     * @param time 自定义 token 默认超时时长，单位为毫秒
     */
    @Override
    public void setDefaultExpireTime(final long time) {
        defaultExpireTime = 0L == time ? defaultExpireTime : time;
    }

    /**
     * 自定义当记住我字段的值为和值时为启用记住我功能，默认值为 "true"
     *
     * @param value 字段值
     */
    @Override
    public void setRmbValue(final String value) {
        if (null != value) {
            rmbValue = value;
        }
    }

    /* 字段 */

    /**
     * 自定义 token 名
     *
     * @param name 自定义 token 的 cookie 名
     */
    @Override
    public void setTokenName(final String name) {
        if (null != name) {
            tokenName = name;
        }
    }

    /**
     * 自定义角色字段名
     *
     * @param parameter 角色字段名
     */
    @Override
    public void setRoleParameter(final String parameter) {
        if (null != parameter) {
            roleParameter = parameter;
        }
    }

    /**
     * 从主体获取角色
     *
     * @param principal 主体对象
     * @return 角色名
     */
    private String getRole(final Object principal) {
        String role;
        try {
            final Class<?> principalClass = principal.getClass();
            final Field roleField = principalClass.getDeclaredField(roleParameter);
            roleField.setAccessible(true);
            role = (String) roleField.get(principal);
        } catch (final NoSuchFieldException | IllegalAccessException e) {
            role = null;
        }
        return role;
    }

    /**
     * 自定义记住我的字段名，默认值为 "remember"
     *
     * @param parameter 字段名
     */
    @Override
    public void setRmbParameter(final String parameter) {
        if (null != parameter) {
            rmbParameter = parameter;
        }
    }

    /* 回调 */

    /**
     * 自定义 token 中存放的额外信息
     *
     * @param claim 返回信息键值对的回调函数
     *              该回调函数需要传入一个包含登录成功后的实体信息 {@link Authentication} 并生成一系列需要存入 token 的额外信息 claim 键值对表并返回
     */
    @Override
    public void setClaimCallback(final Function<? super Authentication, ? extends Map<String, String>> claim) {
        claimCallback = claim;
    }

    /**
     * 成功时 cookies 的内容，在此基础上加入 token
     *
     * @param request    登录请求内容
     * @param authResult 认证成功获得的实体信息
     * @return cookie 列表
     */
    @Override
    public List<Cookie> getCookies(final HttpServletRequest request, final Authentication authResult) {
        final List<Cookie> cookies = super.getCookies(request, authResult);
        /* 获取是否记住我 */
        final String rememberMeStr = request.getParameter(rmbParameter);
        final boolean isRememberMe = Objects.equals(rememberMeStr, rmbValue);
        /* 根据是否记住我来设置超时时间 */
        final long expireTime = isRememberMe ? rmbExpireTime : defaultExpireTime;
        /* 获取 claim */
        final Map<String, String> claim = new HashMap<>(Number.INITIAL_CAPACITY);
        if (null != claimCallback) {
            final Map<String, String> claims = claimCallback.apply(authResult);
            claim.putAll(claims);
        }
        /* 获取角色并存入 claim */
        final Object principal = authResult.getPrincipal();
        final String role = getRole(principal);
        if (null != role) {
            claim.put(roleParameter, role);
        }
        /* 设置 token */
        final String name = authResult.getName();
        final String secret = secretCallback.apply(request);
        final String jwt = JwtUtils.sign(name, claim, expireTime, secret);
        final Cookie token = CookieUtils.generateCookie(tokenName, jwt, Path.ROOT, (int) expireTime);
        /* 将 token 加入 cookies */
        cookies.add(token);
        return cookies;
    }
}
