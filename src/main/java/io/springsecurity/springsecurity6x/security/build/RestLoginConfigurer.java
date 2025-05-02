package io.springsecurity.springsecurity6x.security.build;

import io.springsecurity.springsecurity6x.security.build.option.RestOptions;
import io.springsecurity.springsecurity6x.security.dsl.authentication.single.RestAuthenticationConfigurer;
import io.springsecurity.springsecurity6x.security.init.AuthenticationConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class RestLoginConfigurer implements IdentitySecurityConfigurer {
    @Override
    public boolean supports(AuthenticationConfig config) {
        return "rest".equals(config.type());
    }

    @Override
    public void configure(HttpSecurity http, AuthenticationConfig config) throws Exception {
        RestOptions options = (RestOptions) config.options();
        if (options.matchers() != null && !options.matchers().isEmpty()) {
            http.securityMatcher(options.matchers().toArray(new String[0]));
        }
        http.with(new RestAuthenticationConfigurer(), rest -> {
            rest
                .loginProcessingUrl(options.loginProcessingUrl())
                .defaultSuccessUrl(options.defaultSuccessUrl())
                .failureUrl(options.failureUrl());

            if (options.successHandler() != null) {
                rest.successHandler(options.successHandler());
            } else {
//                rest.successHandler(authenticationHandlers.successHandler());
            }

            if (options.failureHandler() != null) {
                rest.failureHandler(options.failureHandler());
            } else {
//                rest.failureHandler(authenticationHandlers.failureHandler());
            }

            if (options.securityContextRepository() != null) {
                rest.securityContextRepository(options.securityContextRepository());
            }
        });
    }

    @Override
    public void init(HttpSecurity http) throws Exception {

    }

    @Override
    public int order() {
        return 0;
    }
}
