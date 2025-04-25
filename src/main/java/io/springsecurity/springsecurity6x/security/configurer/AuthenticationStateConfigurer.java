package io.springsecurity.springsecurity6x.security.configurer;

import io.springsecurity.springsecurity6x.security.configurer.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.security.configurer.state.JwtStateStrategy;
import io.springsecurity.springsecurity6x.security.configurer.state.SessionStateStrategy;
import io.springsecurity.springsecurity6x.security.exceptionhandling.TokenAuthenticationEntryPoint;
import io.springsecurity.springsecurity6x.security.filter.JwtAuthorizationFilter;
import io.springsecurity.springsecurity6x.security.handler.TokenLogoutHandler;
import io.springsecurity.springsecurity6x.security.handler.SecurityLogoutSuccessHandler;
import io.springsecurity.springsecurity6x.security.token.service.JwtsTokenProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

public class AuthenticationStateConfigurer extends AbstractHttpConfigurer<AuthenticationStateConfigurer, HttpSecurity> {

    private final HttpSecurity http;
    private AuthenticationStateStrategy stateStrategy;
    private boolean configured = false;

    public AuthenticationStateConfigurer(HttpSecurity http) {
        this.http = http;
        this.stateStrategy = new SessionStateStrategy(); // 기본은 세션
    }

    public AuthenticationStateConfigurer useJwt(Customizer<JwtStateStrategy> customizer) {
        assertNotConfigured();
        configured = true;

        JwtStateStrategy jwt = new JwtStateStrategy();
        customizer.customize(jwt);
        this.stateStrategy = jwt;

        return this;
    }

    public AuthenticationStateConfigurer useSession(Customizer<SessionStateStrategy> customizer) {
        assertNotConfigured();
        configured = true;

        SessionStateStrategy session = new SessionStateStrategy();
        customizer.customize(session);
        this.stateStrategy = session;

        return this;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        if (stateStrategy instanceof JwtStateStrategy jwt) {

            http.setSharedObject(SecurityContextRepository.class, new NullSecurityContextRepository());

            JwtsTokenProvider tokenService = (JwtsTokenProvider) jwt.tokenService();
            TokenLogoutHandler logoutHandler = new TokenLogoutHandler(tokenService);
            http.addFilterAfter(new JwtAuthorizationFilter(tokenService, logoutHandler), ExceptionTranslationFilter.class);

            http.logout(logout -> logout
                    .addLogoutHandler(logoutHandler)
                    .logoutSuccessHandler(new SecurityLogoutSuccessHandler()));

            http.exceptionHandling(ex -> ex
                    .authenticationEntryPoint(new TokenAuthenticationEntryPoint()));
        }
    }

    public AuthenticationStateStrategy buildStrategy() {
        return stateStrategy;
    }

    private void assertNotConfigured() {
        if (configured) {
            throw new IllegalStateException("Authentication state already configured");
        }
    }
}


