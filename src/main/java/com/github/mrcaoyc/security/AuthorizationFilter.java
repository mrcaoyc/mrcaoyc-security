package com.github.mrcaoyc.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.mrcaoyc.common.exception.BaseErrorMessage;
import com.github.mrcaoyc.common.exception.ErrorMessage;
import com.github.mrcaoyc.security.event.AuthorizationEvent;
import com.github.mrcaoyc.security.event.AuthorizationListener;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Vector;

/**
 * @author CaoYongCheng
 */
@Slf4j
public class AuthorizationFilter implements Filter {
    private TokenProperties tokenProperties;
    private Vector<AuthorizationListener> listeners = new Vector<>();
    private AuthorizationListener authorizationListener;

    public AuthorizationFilter(TokenProperties tokenProperties) {
        Assert.notNull(tokenProperties, "tokenProperties is null");
        this.tokenProperties = tokenProperties;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        // enable为false表示不进行认证拦截
        if (!tokenProperties.isEnabled()) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        // 判断是否需要跳过改请求
        if (skipIntercept(httpServletRequest)) {
            chain.doFilter(request, response);
            return;
        }

        // 如果令牌缺失则，直接返回错误提示
        String token = httpServletRequest.getHeader(tokenProperties.getAuthKey());
        if (StringUtils.isEmpty(StringUtils.trimWhitespace(token))) {
            writeErrorMessage(httpServletResponse, TokenErrorMessage.ACCESS_TOKEN_MISSING, HttpStatus.UNAUTHORIZED);
            return;
        }

        // 如果验证不通过，则提交终止
        if (!before(httpServletRequest, httpServletResponse, token)) {
            return;
        }


        // 返回时回调处理
        after(httpServletRequest, httpServletResponse);
    }

    /**
     * 注册事件监听器
     *
     * @param listener 监听器
     */
    public void addAuthorizationListener(AuthorizationListener listener) {
        listeners.addElement(listener);
    }

    /**
     * 移除事件监听器
     *
     * @param listener 监听器
     */
    public void removeAuthorizationListener(AuthorizationListener listener) {
        listeners.remove(listener);
    }

    /**
     * 认证成功后相应的事件
     *
     * @param event 事件
     */
    public void authenticationSuccess(AuthorizationEvent event) {
        listeners.forEach(listener -> listener.authorizationSuccess(event));
    }

    /**
     * 可以终止filter执行，提前返回结果，如遇到什么验证不通过问题
     *
     * @param request  请求
     * @param response 响应
     * @param token    获取的令牌，到这里已经表示不会为空
     * @return 如果为true，表示继续执行，false表示提前终止
     */
    protected boolean before(HttpServletRequest request, HttpServletResponse response, String token) {
        return true;
    }

    /**
     * 返回时执行的方法
     *
     * @param request  请求
     * @param response 响应
     */
    protected void after(HttpServletRequest request, HttpServletResponse response) {
    }

    /**
     * 输出错误的信息
     *
     * @param response     响应
     * @param errorMessage 错误信息
     * @param httpStatus   http状态码
     */
    protected void writeErrorMessage(HttpServletResponse response, BaseErrorMessage errorMessage, HttpStatus httpStatus) {
        try (OutputStreamWriter outputStreamWriter = new OutputStreamWriter(response.getOutputStream(),
                StandardCharsets.UTF_8)) {
            response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
            response.setStatus(httpStatus.value());
            ObjectMapper objectMapper = new ObjectMapper();
            String jsonStr = objectMapper.writeValueAsString(
                    new ErrorMessage(errorMessage.getCode(), errorMessage.getMessage()));
            outputStreamWriter.write(jsonStr);
            outputStreamWriter.flush();
        } catch (Exception e) {
            log.error("认证不通过,错误消息:{}.", e.getMessage());
        }
    }


    /**
     * 判断是否需要跳过对该请求的拦截
     *
     * @param request 请求
     * @return 如果为true，表示不进行拦截，为false表示进行拦截
     */
    private boolean skipIntercept(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        AntPathMatcher matcher = new AntPathMatcher();
        return tokenProperties.getExcludeUrls().stream().anyMatch(uri -> matcher.match(uri, requestURI));
    }
}
