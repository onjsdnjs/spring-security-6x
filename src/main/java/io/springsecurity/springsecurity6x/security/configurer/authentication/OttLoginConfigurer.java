package io.springsecurity.springsecurity6x.security.configurer.authentication;

import io.springsecurity.springsecurity6x.security.configurer.state.AuthenticationStateStrategy;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class OttLoginConfigurer implements AuthenticationConfigurer{

    private String loginUrl = "/login/ott";
    private String tokenGenerationUrl = "/ott/generate";
    private OneTimeTokenService tokenService;
    private AuthenticationStateStrategy stateStrategy;

    public OttLoginConfigurer loginProcessingUrl(String url) {
        this.loginUrl = url;
        return this;
    }

    public OttLoginConfigurer tokenGeneratingUrl(String url) {
        this.tokenGenerationUrl = url;
        return this;
    }

    public OttLoginConfigurer tokenService(OneTimeTokenService service) {
        this.tokenService = service;
        return this;
    }

    public void stateStrategy(AuthenticationStateStrategy strategy) {
        this.stateStrategy = strategy;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .oneTimeTokenLogin(ott -> ott
                        .defaultSubmitPageUrl(loginUrl)
                        .showDefaultSubmitPage(true)
                        .tokenGeneratingUrl(tokenGenerationUrl)
                        .tokenService(tokenService) // 예시
                        .authenticationSuccessHandler(stateStrategy::onAuthenticationSuccess)
                );
    }
}

