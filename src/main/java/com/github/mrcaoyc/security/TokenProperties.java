package com.github.mrcaoyc.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * @author CaoYongCheng
 */
@ConfigurationProperties(prefix = "security")
@Data
public class TokenProperties {
    /**
     * 是否启用安全验证
     */
    private boolean enabled = true;

    /**
     * 参数名称
     */
    private String authKey = "Authorization";

    /**
     * 过滤器初始化序号
     */
    private Integer order = 0;

    /**
     * 需要拦截的路径
     */
    private List<String> includeUrls = new ArrayList<>();

    /**
     * 需要排除的路径
     */
    private List<String> excludeUrls = new ArrayList<>();

    /**
     * 过期时间（单位秒）
     */
    private long expiresIn = 60 * 60L;

    /**
     * 刷新过期时间（单位秒）
     */
    private long refreshExpiresIn = 24 * 60 * 60L;
}
