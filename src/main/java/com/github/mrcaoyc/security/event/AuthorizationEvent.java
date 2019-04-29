package com.github.mrcaoyc.security.event;

import java.util.EventObject;
import java.util.Map;

/**
 * @author CaoYongCheng
 */
public class AuthorizationEvent extends EventObject {
    private Map<String, Object> source;

    public AuthorizationEvent(Map<String, Object> source) {
        super(source);
        this.source = source;
    }

    @Override
    public Map<String, Object> getSource() {
        return source;
    }
}
