package com.xumumi.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.springframework.lang.NonNull;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;

/**
 * jwt 处理工具
 *
 * @author XUMUMI
 * @since 1.9
 */
public class JwtUtils {
    /**
     * 验证令牌是否有效
     *
     * @param token  令牌，不可为 null
     * @param secret 密钥，不可为 null
     * @return 有效布尔值
     */
    public static boolean verify(@NonNull String token, @NonNull String secret) {
        try {
            JWT.require(Algorithm.HMAC256(secret)).withSubject(getSubject(token)).build().verify(token);
            return true;
        } catch (JWTVerificationException exception) {
            return false;
        }
    }

    /**
     * 获取令牌主体
     *
     * @param token 令牌
     * @return 主体名
     */
    public static String getSubject(@NonNull String token) {
        return JWT.decode(token).getSubject();
    }

    /**
     * 获取令牌中的信息
     *
     * @param token 令牌
     * @param name  信息名
     * @return 信息内容
     */
    public static String getClaim(@NonNull String token, @NonNull String name) {
        try {
            return JWT.decode(token).getClaim(name).asString();
        } catch (JWTDecodeException e) {
            return null;
        }
    }

    /**
     * 签发令牌
     *
     * @param subject    主体，不可为 null
     * @param claim      附加信息
     * @param expireTime 令牌过期时间
     * @param secret     密钥，不可为 null
     * @return token  令牌
     */
    public static String sign(@NonNull String subject, Map<String, String> claim, long expireTime, @NonNull String secret) {
        try {
            JWTCreator.Builder jwt = JWT.create();
            if (claim != null) {
                claim.forEach(jwt::withClaim);
            }
            return jwt.withSubject(subject)
                    .withExpiresAt(new Date(System.currentTimeMillis() + expireTime))
                    .sign(Algorithm.HMAC256(secret));
        } catch (JWTCreationException e) {
            return null;
        }
    }

    /**
     * 验证令牌是否过期
     *
     * @param token 令牌
     * @return 是否过期布尔值
     */
    public static boolean isExpired(String token) {
        Date now = Calendar.getInstance().getTime();
        return JWT.decode(token)
                .getExpiresAt()
                .before(now);
    }
}
