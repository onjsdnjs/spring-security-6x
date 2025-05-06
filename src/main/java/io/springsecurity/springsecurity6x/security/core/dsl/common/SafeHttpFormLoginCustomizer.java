package io.springsecurity.springsecurity6x.security.core.dsl.common;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;

@FunctionalInterface
public interface SafeHttpFormLoginCustomizer {
    void customize(FormLoginConfigurer<HttpSecurity> formLogin) throws Exception;
}
