package io.springsecurity.springsecurity6x.security.core.dsl.option;

import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import lombok.Getter;
import org.springframework.util.Assert;

import java.util.Objects;

@Getter
public final class FormOptions extends AuthenticationProcessingOptions {

    private final String loginPage;
    private final String usernameParameter;
    private final String passwordParameter;
    private final String defaultSuccessUrl;
    private final String failureUrl;
    private final boolean permitAll;
    private final boolean alwaysUseDefaultSuccessUrl;
    private final SafeHttpFormLoginCustomizer rawFormLoginCustomizers;

    private FormOptions(Builder builder) {
        super(builder);
        this.loginPage = builder.loginPage;
        this.usernameParameter = Objects.requireNonNull(builder.usernameParameter, "usernameParameter cannot be null");
        this.passwordParameter = Objects.requireNonNull(builder.passwordParameter, "passwordParameter cannot be null");
        this.defaultSuccessUrl = builder.defaultSuccessUrl; // targetUrl과 별개로 FormLoginConfigurer에 사용
        this.failureUrl = builder.failureUrl;
        this.permitAll = builder.permitAll;
        this.alwaysUseDefaultSuccessUrl = builder.alwaysUseDefaultSuccessUrl;
        this.rawFormLoginCustomizers = builder.rawFormLoginCustomizers;
    }

    public String getLoginProcessingUrl() {
        return super.getLoginProcessingUrl();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<FormOptions, Builder> {
        private String loginPage = "/loginForm"; // 기본 로그인 페이지 URL 수정
        private String usernameParameter = "username";
        private String passwordParameter = "password";
        private String defaultSuccessUrl = "/";
        private String failureUrl = "/loginForm?error"; // 기본 실패 URL 수정
        private boolean permitAll = false;
        private boolean alwaysUseDefaultSuccessUrl = false;
        private SafeHttpFormLoginCustomizer rawFormLoginCustomizers;

        public Builder() {
            super.loginProcessingUrl("/login"); // Form 인증 처리 URL 기본값
        }

        @Override
        protected Builder self() {
            return this;
        }

        public Builder loginPage(String loginPage) {
            Assert.hasText(loginPage, "loginPage cannot be empty");
            this.loginPage = loginPage;
            return this;
        }

        public Builder usernameParameter(String usernameParameter) {
            Assert.hasText(usernameParameter, "usernameParameter cannot be empty");
            this.usernameParameter = usernameParameter;
            return this;
        }

        public Builder passwordParameter(String passwordParameter) {
            Assert.hasText(passwordParameter, "passwordParameter cannot be empty");
            this.passwordParameter = passwordParameter;
            return this;
        }

        public Builder defaultSuccessUrl(String defaultSuccessUrl) {
            this.defaultSuccessUrl = defaultSuccessUrl;
            this.alwaysUseDefaultSuccessUrl = false; // 명시적으로 false로 설정
            return this;
        }

        public Builder defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
            this.defaultSuccessUrl = defaultSuccessUrl;
            this.alwaysUseDefaultSuccessUrl = alwaysUse;
            return this;
        }

        public Builder failureUrl(String failureUrl) {
            Assert.hasText(failureUrl, "failureUrl cannot be empty");
            this.failureUrl = failureUrl;
            return this;
        }

        public Builder permitAll() {
            this.permitAll = true;
            return this;
        }

        public Builder alwaysUseDefaultSuccessUrl(boolean alwaysUseDefaultSuccessUrl) {
            this.alwaysUseDefaultSuccessUrl = alwaysUseDefaultSuccessUrl;
            return this;
        }

        public Builder rawFormLogin(SafeHttpFormLoginCustomizer rawFormLoginCustomizers) {
            this.rawFormLoginCustomizers = rawFormLoginCustomizers;
            return this;
        }

        @Override
        public FormOptions build() {
            return new FormOptions(this);
        }
    }
}



