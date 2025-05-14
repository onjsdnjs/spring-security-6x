package io.springsecurity.springsecurity6x.security.core.mfa.options.ott;

import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType; // AuthType enum 경로 가정
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.util.Assert;

public class OttFactorOptions extends FactorAuthenticationOptions {
    private final OneTimeTokenService oneTimeTokenService; // Spring Security의 OneTimeTokenService
    private final String tokenGeneratingUrl; // OTT 코드/링크 생성 요청 URL
    private final String defaultSubmitPageUrl; // OTT 코드/링크 생성 요청 URL
    private final boolean showDefaultSubmitPage; // OTT 코드/링크 생성 요청 URL

    // private 생성자로 변경, Builder를 통해서만 생성
    private OttFactorOptions(Builder builder) {
        super(builder, AuthType.OTT); // 부모 생성자 호출
        this.oneTimeTokenService = builder.oneTimeTokenService;
        this.tokenGeneratingUrl = builder.tokenGeneratingUrl;
        this.defaultSubmitPageUrl = builder.defaultSubmitPageUrl;
        this.showDefaultSubmitPage = builder.showDefaultSubmitPage;
    }

    // Getter 메소드들
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

    // Builder 내부 클래스 정의
    public static class Builder extends FactorAuthenticationOptions.AbstractFactorOptionsBuilder<OttFactorOptions, Builder> {
        private OneTimeTokenService oneTimeTokenService;
        private String tokenGeneratingUrl;
        private String defaultSubmitPageUrl;
        private boolean showDefaultSubmitPage;

        public Builder oneTimeTokenService(OneTimeTokenService oneTimeTokenService) {
            Assert.notNull(oneTimeTokenService, "oneTimeTokenService cannot be null");
            this.oneTimeTokenService = oneTimeTokenService;
            return this;
        }

        public Builder tokenGeneratingUrl(String tokenGeneratingUrl) {
            Assert.hasText(tokenGeneratingUrl, "tokenGeneratingUrl cannot be empty");
            this.tokenGeneratingUrl = tokenGeneratingUrl;
            return this;
        }

        public Builder defaultSubmitPageUrl(String defaultSubmitPageUrl) {
            Assert.hasText(defaultSubmitPageUrl, "tokenGeneratingUrl cannot be empty");
            this.defaultSubmitPageUrl = defaultSubmitPageUrl;
            return this;
        }

        public Builder showDefaultSubmitPage(boolean showDefaultSubmitPage) {
            this.showDefaultSubmitPage = showDefaultSubmitPage;
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
