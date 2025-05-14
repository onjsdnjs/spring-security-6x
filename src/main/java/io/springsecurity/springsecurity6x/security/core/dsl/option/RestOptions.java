package io.springsecurity.springsecurity6x.security.core.dsl.option;

import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import lombok.Getter;
import org.springframework.security.web.context.SecurityContextRepository;

@Getter
public final class RestOptions extends FactorAuthenticationOptions {

    private final String usernameParameter;
    private final String passwordParameter;
    private final SecurityContextRepository securityContextRepository;

    private RestOptions(Builder builder) {
        super(builder);
        this.usernameParameter = builder.usernameParameter;
        this.passwordParameter = builder.passwordParameter;
        this.securityContextRepository = builder.securityContextRepository;
    }

    public String getLoginProcessingUrl() {
        return super.getProcessingUrl();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends FactorAuthenticationOptions.AbstractFactorOptionsBuilder<RestOptions, Builder> {
        private String usernameParameter = "username";
        private String passwordParameter = "password";
        private SecurityContextRepository securityContextRepository;

        public Builder() {
            super.processingUrl("/api/auth/login"); // REST 로그인 처리 URL 기본값 설정
            super.targetUrl("/");
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

        public Builder securityContextRepository(SecurityContextRepository securityContextRepository) {
            this.securityContextRepository = securityContextRepository;
            return this;
        }

        @Override
        public RestOptions build() {
            return new RestOptions(this);
        }
    }
}


