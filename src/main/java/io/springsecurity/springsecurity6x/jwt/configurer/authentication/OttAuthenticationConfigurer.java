package io.springsecurity.springsecurity6x.jwt.configurer.authentication;

import io.springsecurity.springsecurity6x.jwt.configurer.state.AuthenticationStateStrategy;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class OttAuthenticationConfigurer implements AuthenticationEntryConfigurer {

    private String loginUrl = "/login/ott";
    private String tokenGenerationUrl = "/ott/generate";
    private OneTimeTokenService tokenService;
    private AuthenticationStateStrategy stateStrategy;

    public OttAuthenticationConfigurer loginProcessingUrl(String url) {
        this.loginUrl = url;
        return this;
    }

    public OttAuthenticationConfigurer tokenGeneratingUrl(String url) {
        this.tokenGenerationUrl = url;
        return this;
    }

    public OttAuthenticationConfigurer tokenService(OneTimeTokenService service) {
        this.tokenService = service;
        return this;
    }

    @Override
    public void setStateStrategy(AuthenticationStateStrategy strategy) {
        this.stateStrategy = strategy;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .oneTimeTokenLogin(ott -> ott
                        .defaultSubmitPageUrl(loginUrl)
                        .tokenGeneratingUrl(tokenGenerationUrl)
                        .tokenService(tokenService)
                        .authenticationSuccessHandler(stateStrategy::onAuthenticationSuccess));
    }
}

