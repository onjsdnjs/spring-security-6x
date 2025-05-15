package io.springsecurity.springsecurity6x.security.core.dsl.option;

import lombok.Getter;

import java.util.Objects;

@Getter
public final class RestOptions extends AuthenticationProcessingOptions {

    private final String usernameParameter;
    private final String passwordParameter;

    private RestOptions(Builder builder) {
        super(builder);
        this.usernameParameter = Objects.requireNonNull(builder.usernameParameter, "usernameParameter cannot be null for RestOptions");
        this.passwordParameter = Objects.requireNonNull(builder.passwordParameter, "passwordParameter cannot be null for RestOptions");
    }

    public String getLoginProcessingUrl() {
        return super.getLoginProcessingUrl();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<RestOptions, Builder> {
        private String usernameParameter = "username";
        private String passwordParameter = "password";

        public Builder() {
            super.loginProcessingUrl("/api/auth/login");
        }

        @Override
        protected Builder self() {
            return this;
        }

        public Builder usernameParameter(String usernameParameter) {
            this.usernameParameter = usernameParameter;
            return this;
        }

        public Builder passwordParameter(String passwordParameter) {
            this.passwordParameter = passwordParameter;
            return this;
        }

        @Override
        public RestOptions build() {
            return new RestOptions(this);
        }
    }
}


