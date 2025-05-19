package io.springsecurity.springsecurity6x.security.core.dsl.option;

import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpFormLoginCustomizer;
import lombok.Getter;
import org.springframework.util.Assert;
import java.util.Objects;

@Getter
public final class FormOptions extends AuthenticationProcessingOptions { // final class

    private final String loginPage;
    private final String usernameParameter;
    private final String passwordParameter;
    private final String defaultSuccessUrl;
    private final String failureUrl;
    private final boolean permitAll;
    private final boolean alwaysUseDefaultSuccessUrl;
    private final SafeHttpFormLoginCustomizer rawFormLoginCustomizer; // final로 변경

    private FormOptions(Builder builder) {
        super(builder);
        this.loginPage = builder.loginPage;
        this.usernameParameter = Objects.requireNonNull(builder.usernameParameter, "usernameParameter cannot be null");
        this.passwordParameter = Objects.requireNonNull(builder.passwordParameter, "passwordParameter cannot be null");
        this.defaultSuccessUrl = builder.defaultSuccessUrl;
        this.failureUrl = builder.failureUrl;
        this.permitAll = builder.permitAll;
        this.alwaysUseDefaultSuccessUrl = builder.alwaysUseDefaultSuccessUrl;
        this.rawFormLoginCustomizer = builder.rawFormLoginCustomizer; // null 가능
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<FormOptions, Builder> {
        private String loginPage = "/loginForm"; // 기본값
        private String usernameParameter = "username"; // 기본값
        private String passwordParameter = "password"; // 기본값
        private String defaultSuccessUrl = "/"; // 기본값
        private String failureUrl = "/loginForm?error"; // 기본값
        private boolean permitAll = false; // 기본값
        private boolean alwaysUseDefaultSuccessUrl = false; // 기본값
        private SafeHttpFormLoginCustomizer rawFormLoginCustomizer;

        public Builder() {
            super.loginProcessingUrl("/login"); // Form 인증 처리 URL 기본값
            // 기본 order 등도 여기서 설정 가능: super.order(100);
        }

        @Override
        protected Builder self() {
            return this;
        }

        public Builder loginPage(String loginPage) {
            Assert.hasText(loginPage, "loginPage cannot be empty or null");
            this.loginPage = loginPage;
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

        public Builder defaultSuccessUrl(String defaultSuccessUrl) {
            this.defaultSuccessUrl = defaultSuccessUrl; // null 허용 가능성 (successHandler 사용 시)
            this.alwaysUseDefaultSuccessUrl = false; // defaultSuccessUrl만 설정 시 alwaysUse는 false
            return this;
        }

        public Builder defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
            this.defaultSuccessUrl = defaultSuccessUrl;
            this.alwaysUseDefaultSuccessUrl = alwaysUse;
            return this;
        }

        public Builder failureUrl(String failureUrl) {
            // Assert.hasText(failureUrl, "failureUrl cannot be empty or null"); // failureHandler 사용 시 null 가능
            this.failureUrl = failureUrl;
            return this;
        }

        public Builder permitAll(boolean permitAll) { // boolean 인자 받도록 변경 (더 명시적)
            this.permitAll = permitAll;
            return this;
        }
        public Builder permitAll() {
            return permitAll(true);
        }

        public Builder alwaysUseDefaultSuccessUrl(boolean alwaysUseDefaultSuccessUrl) {
            this.alwaysUseDefaultSuccessUrl = alwaysUseDefaultSuccessUrl;
            return this;
        }

        public Builder rawFormLoginCustomizer(SafeHttpFormLoginCustomizer rawFormLoginCustomizer) { // 메소드명 변경
            this.rawFormLoginCustomizer = rawFormLoginCustomizer;
            return this;
        }

        @Override
        public FormOptions build() {
            // 빌드 시점에 필수 값 검증 강화 가능
            Assert.hasText(loginProcessingUrl, "loginProcessingUrl must be set for FormOptions");
            return new FormOptions(this);
        }
    }
}