package io.springsecurity.springsecurity6x.security.core.dsl.option;

import lombok.Getter;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.Assert;
import java.util.Objects;

@Getter
public final class OttOptions extends AuthenticationProcessingOptions { // final class

    private final String tokenGeneratingUrl;
    private final String defaultSubmitPageUrl; // null 가능 (showDefaultSubmitPage=false 시)
    private final boolean showDefaultSubmitPage;
    private final OneTimeTokenService oneTimeTokenService; // 필수
    private final OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler; // null 가능

    private OttOptions(Builder builder) {
        super(builder);
        this.tokenGeneratingUrl = Objects.requireNonNull(builder.tokenGeneratingUrl, "tokenGeneratingUrl cannot be null");
        this.defaultSubmitPageUrl = builder.defaultSubmitPageUrl;
        this.showDefaultSubmitPage = builder.showDefaultSubmitPage;
        this.oneTimeTokenService = Objects.requireNonNull(builder.oneTimeTokenService, "oneTimeTokenService cannot be null");
        this.tokenGenerationSuccessHandler = builder.tokenGenerationSuccessHandler;

        if (this.showDefaultSubmitPage) {
            Assert.hasText(this.defaultSubmitPageUrl, "defaultSubmitPageUrl must be set if showDefaultSubmitPage is true");
        }
    }

    public static Builder builder(ApplicationContext applicationContext) {
        return new Builder(applicationContext);
    }

    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<OttOptions, Builder> {
        private String tokenGeneratingUrl = "/ott/generate"; // 기본값
        private String defaultSubmitPageUrl = "/login-ott"; // 기본값
        private boolean showDefaultSubmitPage = true; // 기본값
        private OneTimeTokenService oneTimeTokenService; // 생성자에서 주입
        private OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;

        public Builder(ApplicationContext applicationContext) {
            Objects.requireNonNull(applicationContext, "ApplicationContext cannot be null for OttOptions.Builder");
            this.oneTimeTokenService = applicationContext.getBean(OneTimeTokenService.class);
            super.loginProcessingUrl("/login/ott"); // OTT 인증 처리 URL 기본값
        }

        @Override
        protected Builder self() {
            return this;
        }

        public Builder tokenGeneratingUrl(String url) {
            Assert.hasText(url, "tokenGeneratingUrl cannot be empty or null");
            this.tokenGeneratingUrl = url;
            return this;
        }

        public Builder defaultSubmitPageUrl(String url) {
            // Assert.hasText(url, "defaultSubmitPageUrl cannot be empty or null"); // showDefaultSubmitPage가 false면 필요 없을 수 있음
            this.defaultSubmitPageUrl = url;
            return this;
        }

        public Builder showDefaultSubmitPage(boolean show) {
            this.showDefaultSubmitPage = show;
            return this;
        }

        public Builder oneTimeTokenService(OneTimeTokenService service) {
            this.oneTimeTokenService = Objects.requireNonNull(service, "oneTimeTokenService cannot be null");
            return this;
        }

        public Builder tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
            this.tokenGenerationSuccessHandler = handler; // null 허용 가능 (기본 동작)
            return this;
        }

        @Override
        public OttOptions build() {
            Assert.hasText(loginProcessingUrl, "loginProcessingUrl must be set for OttOptions");
            if (this.showDefaultSubmitPage) {
                Assert.hasText(this.defaultSubmitPageUrl, "defaultSubmitPageUrl must be set if showDefaultSubmitPage is true");
            }
            Objects.requireNonNull(this.oneTimeTokenService, "oneTimeTokenService must be configured for OttOptions");
            return new OttOptions(this);
        }
    }
}
