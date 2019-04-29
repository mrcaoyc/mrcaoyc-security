package com.github.mrcaoyc.security;

import java.util.Map;

/**
 * 令牌生成器
 *
 * @author CaoYongCheng
 */
public interface TokenGenerator {
    /**
     * 创建一个令牌
     *
     * @param payload 令牌中存储的数据
     * @return 令牌
     */
    Token createToken(Map<String, Object> payload);

    /**
     * 解析访问令牌中存储的数据，可以是令牌本身存储的数据，如JWT，也可以是根据令牌存储的缓存数据
     *
     * @param accessToken 访问令牌
     * @return 令牌中存储的数据
     */
    Map<String, Object> parseAccessToken(String accessToken);

    /**
     * 解析刷新令牌中存储的数据，可以是令牌本身存储的数据，如JWT，也可以是根据令牌存储的缓存数据
     *
     * @param refreshToken 刷新令牌
     * @return 令牌中存储的数据
     */
    Map<String, Object> parseRefreshToken(String refreshToken);
}
