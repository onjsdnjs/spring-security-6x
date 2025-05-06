package io.springsecurity.springsecurity6x.security.core.dsl.option;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.List;
import java.util.Objects;

/**
 * Form 인증 방식 전용 옵션 (AbstractOptions 상속)
 */
public final class FormOptions extends AbstractOptions {
    private final String loginPage;
    private final String loginProcessingUrl;
    private final String usernameParameter;
    private final String passwordParameter;
    private final String defaultSuccessUrl;
    private final boolean isAlwaysUseDefaultSuccessUrl;
    private final boolean isPermitAll;
    private final String failureUrl;
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;
    private final SecurityContextRepository securityContextRepository;
    private final Customizer<FormLoginConfigurer<HttpSecurity>> rawFormLogin;

    private FormOptions(Builder b) {
        super(b);
        this.loginPage = b.loginPage;
        this.loginProcessingUrl = b.loginProcessingUrl;
        this.usernameParameter = b.usernameParameter;
        this.passwordParameter = b.passwordParameter;
        this.defaultSuccessUrl = b.defaultSuccessUrl;
        this.isAlwaysUseDefaultSuccessUrl = b.isAlwaysUseDefaultSuccessUrl;
        this.isPermitAll = b.isPermitAll;
        this.failureUrl = b.failureUrl;
        this.successHandler = b.successHandler;
        this.failureHandler = b.failureHandler;
        this.securityContextRepository = b.securityContextRepository;
        this.rawFormLogin = b.rawFormLogin;
    }

    public String getLoginPage() {
        return loginPage;
    }

    public String getLoginProcessingUrl() {
        return loginProcessingUrl;
    }

    public String getUsernameParameter() {
        return usernameParameter;
    }

    public String getPasswordParameter() {
        return passwordParameter;
    }

    public String getDefaultSuccessUrl() {
        return defaultSuccessUrl;
    }

    public boolean isAlwaysUseDefaultSuccessUrl() {
        return isAlwaysUseDefaultSuccessUrl;
    }

    public boolean isPermitAll() {
        return isPermitAll;
    }

    public String getFailureUrl() {
        return failureUrl;
    }

    public AuthenticationSuccessHandler getSuccessHandler() {
        return successHandler;
    }

    public AuthenticationFailureHandler getFailureHandler() {
        return failureHandler;
    }

    public SecurityContextRepository getSecurityContextRepository() {
        return securityContextRepository;
    }

    /**
     * raw FormLoginConfigurer 커스터마이저를 반환합니다.
     */
    public Customizer<FormLoginConfigurer<HttpSecurity>> getRawFormLogin() {
        return rawFormLogin;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends AbstractOptions.Builder<FormOptions, Builder> {
        private String loginPage = "/login";
        private String loginProcessingUrl = "/login";
        private String usernameParameter = "username";
        private String passwordParameter = "password";
        private String defaultSuccessUrl = "/";
        private boolean isAlwaysUseDefaultSuccessUrl = false;
        private boolean isPermitAll = false;
        private String failureUrl = "/login?error";
        private AuthenticationSuccessHandler successHandler;
        private AuthenticationFailureHandler failureHandler;
        private SecurityContextRepository securityContextRepository;
        private Customizer<FormLoginConfigurer<HttpSecurity>> rawFormLogin;

        @Override
        protected Builder self() {
            return this;
        }

        public Builder securityMatchers(List<String> m) {
            return self();
        }

        public Builder loginPage(String u) {
            this.loginPage = Objects.requireNonNull(u, "loginPage must not be null");
            return self();
        }

        public Builder loginProcessingUrl(String u) {
            this.loginProcessingUrl = Objects.requireNonNull(u, "loginProcessingUrl must not be null");
            return self();
        }

        public Builder usernameParameter(String p) {
            this.usernameParameter = Objects.requireNonNull(p, "usernameParameter must not be null");
            return self();
        }

        public Builder passwordParameter(String p) {
            this.passwordParameter = Objects.requireNonNull(p, "passwordParameter must not be null");
            return self();
        }

        public Builder defaultSuccessUrl(String u, boolean alwaysUse) {
            this.defaultSuccessUrl = Objects.requireNonNull(u, "defaultSuccessUrl must not be null");
            this.isAlwaysUseDefaultSuccessUrl = alwaysUse;
            return self();
        }

        public Builder isPermitAll() {
            this.isAlwaysUseDefaultSuccessUrl = true;
            return self();
        }

        public Builder failureUrl(String u) {
            this.failureUrl = Objects.requireNonNull(u, "failureUrl must not be null");
            return self();
        }

        public Builder successHandler(AuthenticationSuccessHandler h) {
            this.successHandler = Objects.requireNonNull(h, "successHandler must not be null");
            return self();
        }

        public Builder failureHandler(AuthenticationFailureHandler h) {
            this.failureHandler = Objects.requireNonNull(h, "failureHandler must not be null");
            return self();
        }

        public Builder securityContextRepository(SecurityContextRepository r) {
            this.securityContextRepository = Objects.requireNonNull(r, "securityContextRepository must not be null");
            return self();
        }

        public Builder rawFormLogin(Customizer<FormLoginConfigurer<HttpSecurity>> c) {
            this.rawFormLogin = Objects.requireNonNull(c, "rawFormLogin customizer must not be null");
            return self();
        }

        @Override
        public FormOptions build() {
            return new FormOptions(this);
        }
    }
}



