package io.springsecurity.springsecurity6x.security.core.dsl.option;

import lombok.Getter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.List;
import java.util.Objects;

/**
 * REST API 로그인 인증 옵션을 immutable 으로 제공하는 클래스.
 */
@Getter
public final class RestOptions extends AbstractOptions {

    private final String loginProcessingUrl;
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;
    private final SecurityContextRepository securityContextRepository;

    private RestOptions(Builder b) {
        super(b);
        this.loginProcessingUrl = b.loginProcessingUrl;
        this.successHandler = b.successHandler;
        this.failureHandler = b.failureHandler;
        this.securityContextRepository = b.securityContextRepository;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends AbstractOptions.Builder<RestOptions, Builder> {
        private String loginProcessingUrl = "/api/auth/login";
        private AuthenticationSuccessHandler successHandler;
        private AuthenticationFailureHandler failureHandler;
        private SecurityContextRepository securityContextRepository;

        @Override
        protected Builder self() {
            return this;
        }

        public Builder loginProcessingUrl(String url) {
            this.loginProcessingUrl = Objects.requireNonNull(url, "loginProcessingUrl must not be null");
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
            return new RestOptions(this);
        }
    }
}

