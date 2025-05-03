package io.springsecurity.springsecurity6x.security.core.feature.option;

import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.List;
import java.util.Objects;

/**
 * REST API 로그인 인증 옵션을 immutable으로 제공하는 클래스.
 */
public final class RestOptions extends AbstractOptions {

    private final List<String> matchers;
    private final String loginProcessingUrl;
    private final String defaultSuccessUrl;
    private final String failureUrl;
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;
    private final SecurityContextRepository securityContextRepository;

    private RestOptions(Builder b) {
        super(b);
        this.matchers = List.copyOf(b.matchers);
        this.loginProcessingUrl = b.loginProcessingUrl;
        this.defaultSuccessUrl = b.defaultSuccessUrl;
        this.failureUrl = b.failureUrl;
        this.successHandler = b.successHandler;
        this.failureHandler = b.failureHandler;
        this.securityContextRepository = b.securityContextRepository;
    }

    public List<String> getMatchers() {
        return matchers;
    }

    public String getLoginProcessingUrl() {
        return loginProcessingUrl;
    }

    public String getDefaultSuccessUrl() {
        return defaultSuccessUrl;
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

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends AbstractOptions.Builder<RestOptions, Builder> {
        private List<String> matchers = List.of("/**");
        private String loginProcessingUrl = "/api/auth/login";
        private String defaultSuccessUrl = "/";
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

        public Builder loginProcessingUrl(String url) {
            this.loginProcessingUrl = Objects.requireNonNull(url, "loginProcessingUrl must not be null");
            return this;
        }

        public Builder defaultSuccessUrl(String url) {
            this.defaultSuccessUrl = Objects.requireNonNull(url, "defaultSuccessUrl must not be null");
            return this;
        }

        public Builder failureUrl(String url) {
            this.failureUrl = Objects.requireNonNull(url, "failureUrl must not be null");
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
        public RestOptions build() {
            if (matchers.isEmpty()) {
                throw new IllegalStateException("At least one matcher is required");
            }
            return new RestOptions(this);
        }
    }
}

