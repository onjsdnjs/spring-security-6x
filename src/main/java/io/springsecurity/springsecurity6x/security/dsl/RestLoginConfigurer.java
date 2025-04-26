package io.springsecurity.springsecurity6x.security.dsl;

import io.springsecurity.springsecurity6x.security.filter.RestAuthenticationFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

public final class RestLoginConfigurer extends AbstractAuthenticationFilterConfigurer<HttpSecurity, RestLoginConfigurer, RestAuthenticationFilter> {

    public RestLoginConfigurer() {
        super(new RestAuthenticationFilter("/api/auth/login",
                new RequestAttributeSecurityContextRepository()), "/api/auth/login");
    }

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return null;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {

        RestAuthenticationFilter filter = getAuthenticationFilter();
        AuthenticationManager manager = http.getSharedObject(AuthenticationManager.class);

        if (manager != null) {
            filter.setAuthenticationManager(manager);
        }
    }

    public void authenticationManager(AuthenticationManager authenticationManager) {

    }
}

