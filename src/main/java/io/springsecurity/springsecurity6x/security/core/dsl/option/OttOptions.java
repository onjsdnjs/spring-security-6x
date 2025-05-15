package io.springsecurity.springsecurity6x.security.core.dsl.option;

import lombok.Getter;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.Assert;

import java.util.Objects;

@Getter
public final class OttOptions extends AuthenticationProcessingOptions {

    private final String tokenGeneratingUrl;
    private final String tokenParameterName;
    private final String defaultSubmitPageUrl;
    private final boolean showDefaultSubmitPage;
    private final OneTimeTokenService oneTimeTokenService;
    private final String oneTimeTokenServiceBeanName;
    private final OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;

    private OttOptions(Builder builder) {
        super(builder);
        this.tokenGeneratingUrl = Objects.requireNonNull(builder.tokenGeneratingUrl, "tokenGeneratingUrl cannot be null");
        this.tokenParameterName = Objects.requireNonNull(builder.tokenParameterName, "tokenParameterName cannot be null");
        this.defaultSubmitPageUrl = builder.defaultSubmitPageUrl;
        this.showDefaultSubmitPage = builder.showDefaultSubmitPage;
        this.oneTimeTokenService = builder.oneTimeTokenService;
        this.oneTimeTokenServiceBeanName = builder.oneTimeTokenServiceBeanName;
        this.tokenGenerationSuccessHandler = builder.tokenGenerationSuccessHandler;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<OttOptions, Builder> {
        private String tokenGeneratingUrl = "/ott/generate";
        private String tokenParameterName = "token";
        private String defaultSubmitPageUrl = "/login-ott";
        private boolean showDefaultSubmitPage = true;
        private OneTimeTokenService oneTimeTokenService;
        private String oneTimeTokenServiceBeanName;
        private OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;

        public Builder() {
            super.loginProcessingUrl("/login/ott");
        }

        @Override
        protected Builder self() {
            return this;
        }

        public Builder tokenGeneratingUrl(String url) {
            Assert.hasText(url, "tokenGeneratingUrl cannot be empty");
            this.tokenGeneratingUrl = url;
            return this;
        }

        public Builder tokenParameterName(String name) {
            Assert.hasText(name, "tokenParameterName cannot be empty");
            this.tokenParameterName = name;
            return this;
        }

        public Builder defaultSubmitPageUrl(String url) {
            this.defaultSubmitPageUrl = url;
            return this;
        }

        public Builder showDefaultSubmitPage(boolean show) {
            this.showDefaultSubmitPage = show;
            return this;
        }

        public Builder oneTimeTokenService(OneTimeTokenService service) {
            this.oneTimeTokenService = service;
            this.oneTimeTokenServiceBeanName = null;
            return this;
        }

        public Builder oneTimeTokenServiceBeanName(String beanName) {
            Assert.hasText(beanName, "oneTimeTokenServiceBeanName cannot be empty");
            this.oneTimeTokenServiceBeanName = beanName;
            this.oneTimeTokenService = null;
            return this;
        }

        public Builder tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
            this.tokenGenerationSuccessHandler = handler;
            return this;
        }

        @Override
        public OttOptions build() {
            Assert.isTrue(oneTimeTokenService != null || oneTimeTokenServiceBeanName != null,
                    "Either oneTimeTokenService or oneTimeTokenServiceBeanName must be set for OTT options.");
            Assert.hasText(super.loginProcessingUrl, "Processing URL (loginProcessingUrl) must be set for OTT options.");
            return new OttOptions(this);
        }
    }
}
