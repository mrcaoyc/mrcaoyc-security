package com.github.mrcaoyc.security;

import lombok.Data;

/**
 * @author CaoYongCheng
 */
@Data
public class Token {
    /**
     * 访问令牌
     */
    private String accessToken;

    /**
     * 刷新令牌
     */
    private String refreshToken;

    /**
     * 过期时间
     */
    private long expiresIn;

    /**
     * 访问令牌Id
     */
    private long accessTokenId;

    /**
     * 刷新令牌Id
     */
    private long refreshTokenId;
}
