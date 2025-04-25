package io.springsecurity.springsecurity6x.security.configurer.authentication;

import io.springsecurity.springsecurity6x.security.configurer.state.AuthenticationStateStrategy;
import io.springsecurity.springsecurity6x.security.ott.EmailOneTimeTokenService;
import io.springsecurity.springsecurity6x.security.ott.EmailService;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class OttLoginConfigurer implements AuthenticationConfigurer{

    private String loginUrl = "/login/ott";
    private String tokenGenerationUrl = "/ott/generate";
    private OneTimeTokenService tokenService = new EmailOneTimeTokenService(
            new InMemoryOneTimeTokenService(),
            new EmailService(new JavaMailSenderImpl()));

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
                        .showDefaultSubmitPage(false)
                        .tokenGeneratingUrl(tokenGenerationUrl)
                        .tokenService(tokenService) // 예시
                        .authenticationSuccessHandler(stateStrategy::onAuthenticationSuccess)
                );
    }
}

