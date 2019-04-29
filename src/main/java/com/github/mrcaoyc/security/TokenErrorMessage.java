package com.github.mrcaoyc.security;


import com.github.mrcaoyc.common.exception.BaseErrorMessage;

/**
 * Token相关异常信息
 *
 * @author CaoYongCheng
 */
public enum TokenErrorMessage implements BaseErrorMessage {
    /**
     * 用户名或密码错误
     */
    USERNAME_OR_PASSWORD_ERROR("用户名或密码错误！", 4001),
    ACCESS_TOKEN_MISSING("缺失访问令牌", 4002),
    REFRESH_TOKEN_MISSING("缺失刷新令牌", 4003),
    ACCESS_TOKEN_EXPIRED("访问令牌已过期", 4004),
    REFRESH_TOKEN_EXPIRED("刷新令牌已过期", 4005),
    ACCESS_TOKEN_INVALID("无效的访问令牌", 4006),
    REFRESH_TOKEN_INVALID("无效的刷新令牌", 4007),
    ;
    private String message;
    private int code;

    TokenErrorMessage(String message, int code) {
        this.message = message;
        this.code = code;
    }

    @Override
    public String getMessage() {
        return message;
    }

    @Override
    public int getCode() {
        return code;
    }
}
