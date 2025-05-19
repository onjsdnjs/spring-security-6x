package io.springsecurity.springsecurity6x.security.core.dsl.option;

import lombok.Getter;
import org.springframework.util.Assert; // Assert 추가
import java.util.Objects;

@Getter
public final class RestOptions extends AuthenticationProcessingOptions { // final class

    private final String usernameParameter;
    private final String passwordParameter;

    private RestOptions(Builder builder) {
        super(builder);
        this.usernameParameter = Objects.requireNonNull(builder.usernameParameter, "usernameParameter cannot be null");
        this.passwordParameter = Objects.requireNonNull(builder.passwordParameter, "passwordParameter cannot be null");
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<RestOptions, Builder> {
        private String usernameParameter = "username";
        private String passwordParameter = "password";

        public Builder() {
            super.loginProcessingUrl("/api/auth/login"); // REST 인증 처리 URL 기본값
        }

        @Override
        protected Builder self() {
            return this;
        }

        public Builder usernameParameter(String usernameParameter) {
            Assert.hasText(usernameParameter, "usernameParameter cannot be empty or null");
            this.usernameParameter = usernameParameter;
            return this;
        }

        public Builder passwordParameter(String passwordParameter) {
            Assert.hasText(passwordParameter, "passwordParameter cannot be empty or null");
            this.passwordParameter = passwordParameter;
            return this;
        }

        @Override
        public RestOptions build() {
            Assert.hasText(loginProcessingUrl, "loginProcessingUrl must be set for RestOptions");
            Assert.hasText(usernameParameter, "usernameParameter must be set for RestOptions");
            Assert.hasText(passwordParameter, "passwordParameter must be set for RestOptions");
            return new RestOptions(this);
        }
    }
}