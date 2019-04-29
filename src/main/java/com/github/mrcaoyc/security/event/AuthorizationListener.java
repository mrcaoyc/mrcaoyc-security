package com.github.mrcaoyc.security.event;

import java.util.EventListener;

/**
 * @author CaoYongCheng
 */
public interface AuthorizationListener extends EventListener {
    /**
     * 认证成功调用的事件
     *
     * @param event 事件
     */
    void authorizationSuccess(AuthorizationEvent event);
}
