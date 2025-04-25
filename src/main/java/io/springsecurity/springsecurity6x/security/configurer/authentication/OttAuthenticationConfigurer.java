package io.springsecurity.springsecurity6x.security.configurer.authentication;

import io.springsecurity.springsecurity6x.security.configurer.state.AuthenticationStateStrategy;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

public class OttAuthenticationConfigurer implements AuthenticationConfigurer{

    private String loginUrl = "/login/ott";
    private String tokenGenerationUrl = "/ott/generate";
    private String defaultSubmitPageUrl = "/login/ott";
    private boolean showDefaultSubmitPage = true;
    private OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;
    private OneTimeTokenService tokenService;

    private AuthenticationStateStrategy stateStrategy;

    public OttAuthenticationConfigurer loginProcessingUrl(String url) {
        this.loginUrl = url;
        return this;
    }

    public OttAuthenticationConfigurer defaultSubmitPageUrl(String url) {
        this.defaultSubmitPageUrl = url;
        return this;
    }

    public OttAuthenticationConfigurer tokenGeneratingUrl(String url) {
        this.tokenGenerationUrl = url;
        return this;
    }

    public OttAuthenticationConfigurer showDefaultSubmitPage(boolean page) {
        this.showDefaultSubmitPage = page;
        return this;
    }

    public OttAuthenticationConfigurer tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
        this.tokenGenerationSuccessHandler = handler;
        return this;
    }

    public OttAuthenticationConfigurer tokenService(OneTimeTokenService service) {
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
                        .defaultSubmitPageUrl(defaultSubmitPageUrl)
                        .loginProcessingUrl(loginUrl)
                        .showDefaultSubmitPage(showDefaultSubmitPage)
                        .tokenGeneratingUrl(tokenGenerationUrl)
                        .tokenService(tokenService)
                        .tokenGenerationSuccessHandler(tokenGenerationSuccessHandler)
                        .authenticationSuccessHandler(stateStrategy::onAuthenticationSuccess)
                );
    }
}

