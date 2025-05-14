package io.springsecurity.springsecurity6x.security.core.dsl.option;

import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import lombok.Getter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;

import java.util.Objects;

@Getter
public final class FormOptions extends FactorAuthenticationOptions {

    private final String loginPage;
    private final String usernameParameter;
    private final String passwordParameter;
    private final String defaultSuccessUrl;
    private final String failureUrl;
    private final boolean permitAll;
    private final boolean alwaysUseDefaultSuccessUrl;
    private final SecurityContextRepository securityContextRepository;

    private FormOptions(Builder builder) {
        super(builder);
        this.loginPage = builder.loginPage;
        this.usernameParameter = Objects.requireNonNull(builder.usernameParameter, "usernameParameter cannot be null");
        this.passwordParameter = Objects.requireNonNull(builder.passwordParameter, "passwordParameter cannot be null");
        this.securityContextRepository = builder.securityContextRepository;
        this.defaultSuccessUrl = builder.defaultSuccessUrl;
        this.failureUrl = builder.failureUrl;
        this.permitAll = builder.permitAll;
        this.alwaysUseDefaultSuccessUrl = builder.alwaysUseDefaultSuccessUrl;
    }

    public String getLoginProcessingUrl() {
        return super.getProcessingUrl();
    }

    public static Builder builder() {
        return new Builder();
    }



    public static final class Builder extends FactorAuthenticationOptions.AbstractFactorOptionsBuilder<FormOptions, Builder> {
        private String loginPage = "/login";
        private String usernameParameter = "username";
        private String passwordParameter = "password";
        private String defaultSuccessUrl = "password";
        private String failureUrl = "password";
        private boolean permitAll = false;
        private boolean alwaysUseDefaultSuccessUrl = false;
        private SecurityContextRepository securityContextRepository;

        public Builder() {
            super.processingUrl("/login");
            super.targetUrl("/");
        }

        @Override
        protected Builder self() {
            return this;
        }

        public Builder loginPage(String loginPage) {
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

        public Builder securityContextRepository(SecurityContextRepository securityContextRepository) {
            this.securityContextRepository = securityContextRepository;
            return this;
        }

        public void defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
            this.defaultSuccessUrl = defaultSuccessUrl;
            this.alwaysUseDefaultSuccessUrl = alwaysUse;
        }

        public void failureUrl(String failureUrl) {
            this.failureUrl = failureUrl;
        }

        public void permitAll() {
            this.permitAll = true;
        }

        public void alwaysUseDefaultSuccessUr(boolean alwaysUseDefaultSuccessUrl) {
            this.alwaysUseDefaultSuccessUrl = alwaysUseDefaultSuccessUrl;
        }

        @Override
        public FormOptions build() {
            return new FormOptions(this);
        }
    }
}




