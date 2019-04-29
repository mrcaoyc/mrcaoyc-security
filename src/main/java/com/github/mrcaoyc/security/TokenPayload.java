package com.github.mrcaoyc.security;

import lombok.Data;

import java.util.Map;

/**
 * @author CaoYongCheng
 */
@Data
public class TokenPayload {
    /**
     * 令牌Id
     */
    private String id;

    /**
     * 令牌中存储的数据
     */
    private Map<String, Object> payload;
}
