package io.springsecurity.springsecurity6x.security.core.dsl.common;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

@FunctionalInterface
public interface SafeHttpCustomizer {
    void customize(HttpSecurity http) throws Exception;
    static <T> Customizer<T> withDefaults() {
        return (t) -> {
        };
    }
}
