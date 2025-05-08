package io.springsecurity.springsecurity6x.security.core.feature.state.jwt;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutHandler;
import io.springsecurity.springsecurity6x.security.handler.logout.JwtLogoutSuccessHandler;
import io.springsecurity.springsecurity6x.security.token.factory.JwtTokenServiceFactory;
import io.springsecurity.springsecurity6x.security.token.service.TokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

public class JwtStateFeature implements StateFeature {

    @Override
    public String getId() {
        return "jwt";
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext ctx) throws Exception {

        TokenService service = JwtTokenServiceFactory.createService(ctx);

        http.setSharedObject(TokenService.class, service);
        http.setSharedObject(LogoutHandler.class, new JwtLogoutHandler(service));
        http.setSharedObject(LogoutSuccessHandler.class, new JwtLogoutSuccessHandler());

        http.with(new JwtStateConfigurer(), Customizer.withDefaults());

    }
}
