package io.springsecurity.springsecurity6x.security.core.feature.state.jwt;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import io.springsecurity.springsecurity6x.security.token.factory.JwtTokenServiceFactory;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class JwtStateFeature implements StateFeature {

    @Override
    public String getId() {
        return "jwt";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {

        TokenService service = JwtTokenServiceFactory.createService(ctx);

        http.setSharedObject(TokenService.class, service);
        http.with(new JwtStateConfigurer(), Customizer.withDefaults());

    }
}
