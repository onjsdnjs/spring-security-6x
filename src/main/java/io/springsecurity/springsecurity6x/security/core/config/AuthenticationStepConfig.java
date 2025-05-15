package io.springsecurity.springsecurity6x.security.core.config;


import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Getter
@Setter
public class AuthenticationStepConfig {
    private String type;
    private final Map<String, Object> options = new HashMap<>();
    private int order = 0; // 기본값

    public AuthenticationStepConfig() {} // 기본 생성자

    public AuthenticationStepConfig(String type, int order) {
        this.type = type;
        this.order = order;
    }

    public void addOption(String key, Object value) {
        this.options.put(key, value);
    }

    public <T> T getOption(String key) {
        return (T) this.options.get(key);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationStepConfig that = (AuthenticationStepConfig) o;
        return order == that.order && Objects.equals(type, that.type) && Objects.equals(options, that.options);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, options, order);
    }
}