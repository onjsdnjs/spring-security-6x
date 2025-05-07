package io.springsecurity.springsecurity6x.security.core.feature.state;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import io.springsecurity.springsecurity6x.security.core.feature.authentication.SessionStateConfigurer;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class SessionStateFeature implements StateFeature {

    @Override
    public String getId() {
        return "session";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {
        SessionStateConfigurer configurer = new SessionStateConfigurer();
        http.with(configurer, Customizer.withDefaults());
    }
}
