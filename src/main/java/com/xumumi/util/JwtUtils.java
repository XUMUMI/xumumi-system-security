package com.xumumi.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.xumumi.filter.constant.Number;
import org.springframework.lang.NonNull;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * jwt 处理工具
 *
 * @author XUMUMI
 * @since 1.9
 */
public enum JwtUtils {
    /* 工具类 */;

    /**
     * 验证令牌是否有效
     *
     * @param token  令牌
     * @param secret 密钥
     * @return 有效布尔值
     */
    public static boolean isValid(final String token, final String secret) {
        boolean result;
        try {
            final Algorithm algorithm = Algorithm.HMAC256(secret);
            final String subject = getSubject(token);
            final JWTVerifier build = JWT.require(algorithm).withSubject(subject).build();
            build.verify(token);
            result = noExpired(token);
        } catch (final JWTVerificationException ignored) {
            result = false;
        }
        return result;
    }

    /**
     * 获取令牌主体
     *
     * @param token 令牌
     * @return 主体名
     */
    public static String getSubject(final String token) {
        final DecodedJWT decode = JWT.decode(token);
        return decode.getSubject();
    }

    /**
     * 获取令牌中的信息
     *
     * @param token  令牌
     * @param secret 用于加密的密钥字符串
     * @param name   信息名
     * @return 信息内容
     */
    public static String getClaimValue(final String token, final String secret, final String name) {
        String claimValue = null;
        if (null != token && null != name && isValid(token, secret)) {
            try {
                final DecodedJWT decode = JWT.decode(token);
                final Claim claim = decode.getClaim(name);
                claimValue = claim.asString();
            } catch (final JWTDecodeException ignored) {
            }
        }
        return claimValue;
    }

    /**
     * 签发令牌
     *
     * @param subject    主体，不可为 null
     * @param claims     附加信息
     * @param expireTime 令牌过期时间
     * @param secret     密钥，不可为 null
     * @return token  令牌
     */
    public static String sign(@NonNull final String subject, final Map<String, String> claims,
                              final long expireTime, @NonNull final String secret) {
        String token;
        try {
            final JWTCreator.Builder jwt = JWT.create();
            if (null != claims) {
                claims.forEach(jwt::withClaim);
            }
            final long currentTime = System.currentTimeMillis();
            final Algorithm algorithm = Algorithm.HMAC256(secret);
            token = jwt.withSubject(subject).withExpiresAt(new Date(currentTime + expireTime)).sign(algorithm);
        } catch (final JWTCreationException e) {
            token = null;
        }
        return token;
    }

    /**
     * 验证令牌是否过期
     *
     * @param token 令牌
     * @return 是否过期布尔值
     */
    private static boolean noExpired(final String token) {
        final Date now = Calendar.getInstance().getTime();
        final DecodedJWT decode = JWT.decode(token);
        final Date expiresAt = decode.getExpiresAt();
        return !expiresAt.before(now);
    }

    /**
     * 刷新令牌，如果令牌无效则返回 null
     *
     * @param token 令牌
     * @return 新令牌
     */
    public static String refresh(final String token, final long expireDuration, @NonNull final String secret) {
        String ret = null;
        if (null != token && isValid(token, secret)) {
            final DecodedJWT decode = JWT.decode(token);
            final long expireTime = decode.getExpiresAt().getTime();
            final long currentTime = System.currentTimeMillis();
            if ((expireTime - currentTime) < expireDuration) {
                final Map<String, String> claims = new HashMap<>(Number.INITIAL_CAPACITY);
                decode.getClaims().forEach((s, claim) -> claims.put(s, claim.asString()));
                ret = sign(decode.getSubject(), claims, expireDuration, secret);
            }
        }
        return ret;
    }
}
