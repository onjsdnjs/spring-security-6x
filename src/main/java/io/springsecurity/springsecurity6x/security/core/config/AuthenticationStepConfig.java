package io.springsecurity.springsecurity6x.security.core.config;

import java.util.Map;
import java.util.HashMap;

/**
 * DSL 단계별 설정 정보
 */
public class AuthenticationStepConfig {
    private String type;
    private String[] matchers;
    private final Map<String, Object> options = new HashMap<>();

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public String[] getMatchers() { return matchers; }
    public void setMatchers(String[] matchers) { this.matchers = matchers; }

    public Map<String, Object> getOptions() { return options; }
}
