package io.springsecurity.springsecurity6x.security.builder;

import io.springsecurity.springsecurity6x.security.config.AuthenticationConfig;
import io.springsecurity.springsecurity6x.security.config.IdentityConfig;
import io.springsecurity.springsecurity6x.security.dsl.option.FormOptions;
import io.springsecurity.springsecurity6x.security.dsl.option.OttOptions;
import io.springsecurity.springsecurity6x.security.dsl.option.PasskeyOptions;
import io.springsecurity.springsecurity6x.security.dsl.option.RestOptions;
import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurerImpl;
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

    public SecurityFilterChain buildChain(AuthenticationConfig config) throws Exception {
        HttpSecurity http = httpSecurityProvider.getObject();

        List<String> matchers = null;
        switch (config.type) {
            case "form" -> matchers = ((FormOptions) config.options).getMatchers();
            case "rest" -> matchers = ((RestOptions) config.options).getMatchers();
            case "passkey" -> matchers = ((PasskeyOptions) config.options).getMatchers();
            case "ott" -> matchers = ((OttOptions) config.options).getMatchers();
        }

        if (matchers != null && !matchers.isEmpty()) {
            http.securityMatcher(matchers.toArray(new String[0]));
        } else {
            switch (config.type) {
                case "rest" -> http.securityMatcher("/api/**");
                case "form", "passkey", "ott" -> http.securityMatcher("/**");
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