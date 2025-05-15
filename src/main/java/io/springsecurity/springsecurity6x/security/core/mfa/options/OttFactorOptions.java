package io.springsecurity.springsecurity6x.security.core.mfa.options;

import io.springsecurity.springsecurity6x.security.enums.AuthType; // AuthType enum 경로 가정
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.util.Assert;

public class OttFactorOptions extends FactorAuthenticationOptions {
    private final OneTimeTokenService oneTimeTokenService; // Spring Security의 OneTimeTokenService
    private final String tokenGeneratingUrl; // OTT 코드/링크 생성 요청 URL
    private final String defaultSubmitPageUrl; // OTT 코드/링크 생성 요청 URL
    private final boolean showDefaultSubmitPage; // OTT 코드/링크 생성 요청 URL

    private OttFactorOptions(Builder builder) {
        super(builder); // 부모 생성자 호출
        this.oneTimeTokenService = builder.oneTimeTokenService;
        this.tokenGeneratingUrl = builder.tokenGeneratingUrl;
        this.defaultSubmitPageUrl = builder.defaultSubmitPageUrl;
        this.showDefaultSubmitPage = builder.showDefaultSubmitPage;
    }

    public OneTimeTokenService getOneTimeTokenService() {
        return oneTimeTokenService;
    }

    public String getTokenGeneratingUrl() {
        return tokenGeneratingUrl;
    }

    public String defaultSubmitPageUrl() {
        return defaultSubmitPageUrl;
    }

    public boolean showDefaultSubmitPage() {
        return showDefaultSubmitPage;
    }

    // static factory method for builder
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends FactorAuthenticationOptions.AbstractFactorOptionsBuilder<OttFactorOptions, Builder> {
        private OneTimeTokenService oneTimeTokenService;
        private String tokenGeneratingUrl;
        private String defaultSubmitPageUrl; // 추가
        private boolean showDefaultSubmitPage; // 추가
        private OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler; // 추가


        public Builder oneTimeTokenService(OneTimeTokenService oneTimeTokenService) {
            this.oneTimeTokenService = oneTimeTokenService;
            return this;
        }

        public Builder tokenGeneratingUrl(String tokenGeneratingUrl) {
            this.tokenGeneratingUrl = tokenGeneratingUrl;
            return this;
        }

        public Builder defaultSubmitPageUrl(String defaultSubmitPageUrl) {
            this.defaultSubmitPageUrl = defaultSubmitPageUrl;
            return this;
        }

        public Builder showDefaultSubmitPage(boolean showDefaultSubmitPage) {
            this.showDefaultSubmitPage = showDefaultSubmitPage;
            return this;
        }

        public Builder tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
            this.tokenGenerationSuccessHandler = handler;
            return this;
        }

        @Override
        protected Builder self() {
            return this;
        }

        @Override
        public OttFactorOptions build() {
            return new OttFactorOptions(this);
        }
    }
}
