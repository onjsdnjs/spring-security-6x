package io.springsecurity.springsecurity6x.security.core.feature.state.jwt;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import io.springsecurity.springsecurity6x.security.token.factory.JwtTokenFactory;
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

        TokenService service = JwtTokenFactory.createService(ctx);
        LogoutHandler logoutHandler = JwtTokenFactory.createLogoutHandler(service);
        LogoutSuccessHandler successHandler = JwtTokenFactory.createLogoutSuccessHandler();

        http.setSharedObject(TokenService.class, service);
        http.setSharedObject(LogoutHandler.class, logoutHandler);
        http.setSharedObject(LogoutSuccessHandler.class, successHandler);

        http.with(new JwtStateConfigurer(), Customizer.withDefaults());

    }
}
