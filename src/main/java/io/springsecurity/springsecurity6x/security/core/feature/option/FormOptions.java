package io.springsecurity.springsecurity6x.security.core.feature.option;

import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.List;
import java.util.Objects;

/**
 * Form 인증 방식 전용 옵션 (AbstractOptions 상속)
 */
public final class FormOptions extends AbstractOptions {
    private final List<String> matchers;
    private final String loginPage;
    private final String loginProcessingUrl;
    private final String usernameParameter;
    private final String passwordParameter;
    private final String defaultSuccessUrl;
    private final boolean alwaysUseDefaultSuccessUrl;
    private final String failureUrl;
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;
    private final SecurityContextRepository securityContextRepository;

    private FormOptions(Builder b) {
        super(b);
        this.matchers = List.copyOf(b.matchers);
        this.loginPage = b.loginPage;
        this.loginProcessingUrl = b.loginProcessingUrl;
        this.usernameParameter = b.usernameParameter;
        this.passwordParameter = b.passwordParameter;
        this.defaultSuccessUrl = b.defaultSuccessUrl;
        this.alwaysUseDefaultSuccessUrl = b.alwaysUseDefaultSuccessUrl;
        this.failureUrl = b.failureUrl;
        this.successHandler = b.successHandler;
        this.failureHandler = b.failureHandler;
        this.securityContextRepository = b.securityContextRepository;
    }

    public List<String> getMatchers() { return matchers; }
    public String getLoginPage() { return loginPage; }
    public String getLoginProcessingUrl() { return loginProcessingUrl; }
    public String getUsernameParameter() { return usernameParameter; }
    public String getPasswordParameter() { return passwordParameter; }
    public String getDefaultSuccessUrl() { return defaultSuccessUrl; }
    public boolean isAlwaysUseDefaultSuccessUrl() { return alwaysUseDefaultSuccessUrl; }
    public String getFailureUrl() { return failureUrl; }
    public AuthenticationSuccessHandler getSuccessHandler() { return successHandler; }
    public AuthenticationFailureHandler getFailureHandler() { return failureHandler; }
    public SecurityContextRepository getSecurityContextRepository() { return securityContextRepository; }

    public static Builder builder() { return new Builder(); }
    public static final class Builder extends AbstractOptions.Builder<FormOptions, Builder> {
        private List<String> matchers = List.of("/**");
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

        @Override
        protected Builder self() {
            return this;
        }

        public Builder matchers(List<String> patterns) {
            this.matchers = Objects.requireNonNull(patterns, "matchers must not be null");
            return this;
        }
        public Builder loginPage(String url) {
            this.loginPage = Objects.requireNonNull(url, "loginPage must not be null");
            return this;
        }
        public Builder loginProcessingUrl(String url) {
            this.loginProcessingUrl = Objects.requireNonNull(url, "loginProcessingUrl must not be null");
            return this;
        }
        public Builder usernameParameter(String name) {
            this.usernameParameter = Objects.requireNonNull(name);
            return this;
        }
        public Builder passwordParameter(String name) {
            this.passwordParameter = Objects.requireNonNull(name);
            return this;
        }
        public Builder defaultSuccessUrl(String url, boolean alwaysUse) {
            this.defaultSuccessUrl = Objects.requireNonNull(url);
            this.alwaysUseDefaultSuccessUrl = alwaysUse;
            return this;
        }
        public Builder failureUrl(String url) {
            this.failureUrl = Objects.requireNonNull(url);
            return this;
        }
        public Builder successHandler(AuthenticationSuccessHandler handler) {
            this.successHandler = handler;
            return this;
        }
        public Builder failureHandler(AuthenticationFailureHandler handler) {
            this.failureHandler = handler;
            return this;
        }
        public Builder securityContextRepository(SecurityContextRepository repo) {
            this.securityContextRepository = repo;
            return this;
        }

        @Override
        public FormOptions build() {
            if (matchers.isEmpty()) {
                throw new IllegalStateException("At least one matcher is required");
            }
            return new FormOptions(this);
        }
    }
}


