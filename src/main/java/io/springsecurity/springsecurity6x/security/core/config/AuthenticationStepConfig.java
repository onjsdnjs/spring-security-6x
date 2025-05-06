package io.springsecurity.springsecurity6x.security.core.config;

import java.util.Map;
import java.util.HashMap;

/**
 * DSL 단계별 설정 정보
 */
public class AuthenticationStepConfig {
    private String type;
    private final Map<String, Object> options = new HashMap<>();

    public String type() { return type; }
    public void type(String type) { this.type = type; }

    public Map<String, Object> options() { return options; }
}
