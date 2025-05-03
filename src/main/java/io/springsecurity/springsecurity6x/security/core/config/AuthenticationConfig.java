package io.springsecurity.springsecurity6x.security.core.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.function.ThrowingConsumer;

public class AuthenticationConfig {
    private final String type;
    private final Object options;
    private final ThrowingConsumer<HttpSecurity> customizer;
    public AuthenticationConfig(String type, Object opts, ThrowingConsumer<HttpSecurity> c) {
        this.type = type;
        this.options = opts;
        this.customizer = c;
    }
    public String type() { return type; }
    public Object options() { return options; }
    public ThrowingConsumer<HttpSecurity> customizer() { return customizer; }
}
