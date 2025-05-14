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
        this.usernameParameter = builder.usernameParameter; // 기본값은 빌더에서 설정
        this.passwordParameter = builder.passwordParameter; // 기본값은 빌더에서 설정
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
            super.processingUrl("/api/auth/login"); // 기본값 설정
            super.targetUrl("/");             // 기본값 설정
        }

        @Override
        protected Builder self() {
            return this;
        }

        public Builder usernameParameter(String usernameParameter) {
            this.usernameParameter = usernameParameter; // null 허용 (기본값 사용 위함)
            return this;
        }

        public Builder passwordParameter(String passwordParameter) {
            this.passwordParameter = passwordParameter; // null 허용 (기본값 사용 위함)
            return this;
        }

        public Builder securityContextRepository(SecurityContextRepository securityContextRepository) {
            this.securityContextRepository = securityContextRepository;
            return this;
        }

        // loginProcessingUrl, targetUrl, successHandler, failureHandler는 부모 빌더의 메소드 사용

        @Override
        public RestOptions build() {
            return new RestOptions(this);
        }
    }
}


