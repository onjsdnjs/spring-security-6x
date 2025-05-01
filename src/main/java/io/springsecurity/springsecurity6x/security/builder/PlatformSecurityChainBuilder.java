package io.springsecurity.springsecurity6x.security.builder;

import io.springsecurity.springsecurity6x.security.config.AuthenticationConfig;
import io.springsecurity.springsecurity6x.security.config.IdentityConfig;
import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurer;
import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurer;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurerImpl;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;


public class PlatformSecurityChainBuilder {

    private final ObjectProvider<HttpSecurity> httpSecurityProvider;
    private final JwtStateConfigurerImpl jwtConfigurer;
    private final SessionStateConfigurerImpl sessionConfigurer;

    public PlatformSecurityChainBuilder(
            ObjectProvider<HttpSecurity> httpSecurityProvider,
            JwtStateConfigurerImpl jwtConfigurer,
            SessionStateConfigurerImpl sessionConfigurer) {

        this.httpSecurityProvider = httpSecurityProvider;
        this.jwtConfigurer = jwtConfigurer;
        this.sessionConfigurer = sessionConfigurer;
    }

    public List<SecurityFilterChain> buildFrom(IdentityConfig config) throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<>();
        for (AuthenticationConfig entry : config.authentications) {
            chains.add(buildChain(entry));
        }
        return chains;
    }

    private SecurityFilterChain buildChain(AuthenticationConfig config) throws Exception {
        HttpSecurity http = httpSecurityProvider.getObject();

        Object matcher = config.options.getValues().get("matchers");
        if (matcher instanceof List<?> matchers) {
            http.securityMatcher(matchers.toArray(String[]::new));
        } else {
            switch (config.type) {
                case "rest" -> http.securityMatcher("/api/**");
                case "form" -> http.securityMatcher("/**");
                case "passkey" -> http.securityMatcher("/**");
                case "ott" -> http.securityMatcher("/**");
            }
        }

        if ("jwt".equals(config.stateType)) {
            http.with(jwtConfigurer, Customizer.withDefaults());

        } else {
            http.with(sessionConfigurer, Customizer.withDefaults());
        }

        if (config.httpCustomizer() != null) {
            config.httpCustomizer().customize(http);
        }

        return http.build();
    }
}