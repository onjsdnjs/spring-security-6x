package io.springsecurity.springsecurity6x.security.core.context;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PlatformContext {
    private final List<AuthenticationConfig> configs = new ArrayList<>();
    private final Map<Class<?>, Object> shared = new HashMap<>();

    public void addAuthConfig(AuthenticationConfig c) {
        configs.add(c);
    }
    public List<AuthenticationConfig> getAuthConfigs() { return List.copyOf(configs); }

    public <T> void share(Class<T> clz, T obj) {
        shared.put(clz, obj);
    }

    public <T> T getShared(Class<T> clz) {
        return (T) shared.get(clz);
    }
}
