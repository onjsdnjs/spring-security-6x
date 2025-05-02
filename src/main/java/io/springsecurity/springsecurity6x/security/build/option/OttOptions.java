package io.springsecurity.springsecurity6x.security.build.option;

import io.springsecurity.springsecurity6x.security.init.configurer.AuthConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.List;

public class OttOptions implements AuthConfigurer {

    private List<String> matchers;
    private String loginProcessingUrl;

    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private SecurityContextRepository securityContextRepository;

    public List<String> matchers() {
        return matchers;
    }

    public void matchers(List<String> matchers) {
        this.matchers = matchers;
    }

    public String loginProcessingUrl() {
        return loginProcessingUrl;
    }

    public void loginProcessingUrl(String loginProcessingUrl) {
        this.loginProcessingUrl = loginProcessingUrl;
    }

    public AuthenticationSuccessHandler successHandler() {
        return successHandler;
    }

    public void successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
    }

    public AuthenticationFailureHandler failureHandler() {
        return failureHandler;
    }

    public void failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
    }

    public SecurityContextRepository securityContextRepository() {
        return securityContextRepository;
    }

    public void securityContextRepository(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        if (matchers != null && !matchers.isEmpty()) {
            http.securityMatcher(matchers.toArray(new String[0]));
        } else {
            http.securityMatcher("/**");
        }
    }
}
