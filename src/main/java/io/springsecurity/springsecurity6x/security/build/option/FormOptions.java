package io.springsecurity.springsecurity6x.security.build.option;

import io.springsecurity.springsecurity6x.security.init.configurer.AuthConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.List;

/**
 * Form 인증 방식에 대한 DSL 옵션 클래스
 */
public class FormOptions implements AuthConfigurer {

    private String loginPage = "/login";
    private String loginProcessingUrl = "/login";
    private String usernameParameter = "username";
    private String passwordParameter = "password";
    private String defaultSuccessUrl = "/";
    private boolean alwaysUseDefaultSuccessUrl = false;
    private String failureUrl = "/login?error";

    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private SecurityContextRepository securityContextRepository;

    private List<String> matchers;

    public String loginPage() {
        return loginPage;
    }

    public void loginPage(String loginPage) {
        this.loginPage = loginPage;
    }
    public String loginProcessingUrl() {
        return loginProcessingUrl;
    }

    public void loginProcessingUrl(String loginProcessingUrl) {
        this.loginProcessingUrl = loginProcessingUrl;
    }

    public String usernameParameter() {
        return usernameParameter;
    }

    public void usernameParameter(String usernameParameter) {
        this.usernameParameter = usernameParameter;
    }

    public String passwordParameter() {
        return passwordParameter;
    }

    public void passwordParameter(String passwordParameter) {
        this.passwordParameter = passwordParameter;
    }

    public String defaultSuccessUrl() {
        return defaultSuccessUrl;
    }

    public void defaultSuccessUrl(String defaultSuccessUrl) {
        this.defaultSuccessUrl = defaultSuccessUrl;
    }

    public boolean alwaysUseDefaultSuccessUrl() {
        return alwaysUseDefaultSuccessUrl;
    }

    public void alwaysUseDefaultSuccessUrl(boolean alwaysUseDefaultSuccessUrl) {this.alwaysUseDefaultSuccessUrl = alwaysUseDefaultSuccessUrl;}

    public String failureUrl() {
        return failureUrl;
    }

    public void failureUrl(String failureUrl) {
        this.failureUrl = failureUrl;
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
    public List<String> matchers() {
        return matchers;
    }

    public void matchers(List<String> matchers) {
        this.matchers = matchers;
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

