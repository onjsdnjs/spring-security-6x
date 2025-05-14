package io.springsecurity.springsecurity6x.security.core.dsl.option;

import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import lombok.Getter;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.Assert;

import java.util.Objects;

@Getter
public final class OttOptions extends FactorAuthenticationOptions {

    private final String tokenGeneratingUrl;
    // processingUrl은 FactorAuthenticationOptions의 getProcessingUrl()을 통해 접근 (코드 제출 URL)
    private final String tokenParameterName;
    private final String defaultSubmitPageUrl;
    private final boolean showDefaultSubmitPage;
    private final OneTimeTokenService oneTimeTokenService;
    private final String oneTimeTokenServiceBeanName;
    private final OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;
    // successHandler, failureHandler, targetUrl은 FactorAuthenticationOptions 에서 상속받음

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

    // public String getProcessingUrl() { return super.getProcessingUrl(); } // 코드 제출 URL

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends FactorAuthenticationOptions.AbstractFactorOptionsBuilder<OttOptions, Builder> {
        private String tokenGeneratingUrl = "/ott/generate";
        private String tokenParameterName = "token";
        private String defaultSubmitPageUrl = "/login-ott";
        private boolean showDefaultSubmitPage = true;
        private OneTimeTokenService oneTimeTokenService;
        private String oneTimeTokenServiceBeanName;
        private OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;

        public Builder() {
            super.processingUrl("/login/ott"); // 코드 제출 URL 기본값
            super.targetUrl("/");
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
            this.oneTimeTokenServiceBeanName = beanName;
            this.oneTimeTokenService = null;
            return this;
        }

        public Builder tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
            this.tokenGenerationSuccessHandler = handler;
            return this;
        }

        // processingUrl, targetUrl, successHandler, failureHandler는 부모 빌더의 메소드 사용

        @Override
        public OttOptions build() {
            Assert.isTrue(oneTimeTokenService != null || oneTimeTokenServiceBeanName != null,
                    "Either oneTimeTokenService or oneTimeTokenServiceBeanName must be set for OTT options.");
            return new OttOptions(this);
        }
    }
}
