package io.springsecurity.springsecurity6x.security.core.config;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeatureRegistry;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class AuthenticationConfigurerChain {
    private final AuthenticationFeatureRegistry registry;

    public AuthenticationConfigurerChain(AuthenticationFeatureRegistry registry) {
        this.registry = registry;
    }

    public void configure(HttpSecurity http, PlatformContext ctx) throws Exception {
        // apply flow-level common settings
        for (AuthenticationConfig ac : ctx.getAuthConfigs()) {
            ac.customizer().accept(http);
        }
        // apply specific authentication features
        registry.configure(http, ctx);
    }
}

