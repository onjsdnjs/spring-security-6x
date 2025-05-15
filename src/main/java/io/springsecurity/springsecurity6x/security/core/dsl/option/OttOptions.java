package io.springsecurity.springsecurity6x.security.core.dsl.option;

import lombok.Getter;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.Assert;

import java.util.Objects;

@Getter
public final class OttOptions extends AuthenticationProcessingOptions {

    private final String tokenGeneratingUrl;
    private final String defaultSubmitPageUrl;
    private final boolean showDefaultSubmitPage;
    private final OneTimeTokenService oneTimeTokenService;
    private final OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;

    private OttOptions(Builder builder) {
        super(builder);
        this.tokenGeneratingUrl = Objects.requireNonNull(builder.tokenGeneratingUrl, "tokenGeneratingUrl cannot be null");
        this.defaultSubmitPageUrl = builder.defaultSubmitPageUrl;
        this.showDefaultSubmitPage = builder.showDefaultSubmitPage;
        this.oneTimeTokenService = builder.oneTimeTokenService;
        this.tokenGenerationSuccessHandler = builder.tokenGenerationSuccessHandler;
    }

    public static Builder builder(ApplicationContext applicationContext) {
        return new Builder(applicationContext);
    }

    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<OttOptions, Builder> {
        private String tokenGeneratingUrl = "/ott/generate";
        private String defaultSubmitPageUrl = "/login-ott";
        private boolean showDefaultSubmitPage = true;
        private OneTimeTokenService oneTimeTokenService;
        private OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;

        public Builder(ApplicationContext applicationContext) {
            this.oneTimeTokenService = applicationContext.getBean(OneTimeTokenService.class);
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
            return this;
        }

        public Builder tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
            this.tokenGenerationSuccessHandler = handler;
            return this;
        }

        @Override
        public OttOptions build() {
            return new OttOptions(this);
        }
    }
}
