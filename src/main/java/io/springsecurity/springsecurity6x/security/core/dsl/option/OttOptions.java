package io.springsecurity.springsecurity6x.security.core.dsl.option;

import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.ott.OneTimeTokenLoginConfigurer;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;

import java.util.List;
import java.util.Objects;

/**
 * OTT(One-Time Token) 인증 옵션을 불변(immutable)으로 제공하는 클래스.
 */
public final class OttOptions extends AbstractOptions {

    private final List<String> matchers;
    private final String loginProcessingUrl;
    private final String defaultSubmitPageUrl;
    private final String tokenGeneratingUrl;
    private final boolean showDefaultSubmitPage;
    private final OneTimeTokenService tokenService;
    private final OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;
    private final Customizer<OneTimeTokenLoginConfigurer<HttpSecurity>> rawOttLogin;

    private OttOptions(Builder b) {
        super(b);
        this.matchers = List.copyOf(b.matchers);
        this.loginProcessingUrl = b.loginProcessingUrl;
        this.defaultSubmitPageUrl = b.defaultSubmitPageUrl;
        this.tokenGeneratingUrl = b.tokenGeneratingUrl;
        this.showDefaultSubmitPage = b.showDefaultSubmitPage;
        this.tokenService = b.tokenService;
        this.tokenGenerationSuccessHandler = b.tokenGenerationSuccessHandler;
        this.rawOttLogin = b.rawOttLogin;
    }

    public List<String> getMatchers() {
        return matchers;
    }

    public String getLoginProcessingUrl() {
        return loginProcessingUrl;
    }

    public String getDefaultSubmitPageUrl() {
        return defaultSubmitPageUrl;
    }

    public String getTokenGeneratingUrl() {
        return tokenGeneratingUrl;
    }

    public boolean isShowDefaultSubmitPage() {
        return showDefaultSubmitPage;
    }

    public OneTimeTokenService getTokenService() {
        return tokenService;
    }

    public OneTimeTokenGenerationSuccessHandler getTokenGenerationSuccessHandler() {
        return tokenGenerationSuccessHandler;
    }
    public Customizer<OneTimeTokenLoginConfigurer<HttpSecurity>> getRawOttLogin() {
        return rawOttLogin;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends AbstractOptions.Builder<OttOptions, Builder> {
        private List<String> matchers = List.of("/**");
        private String loginProcessingUrl = "/login/ott";
        private String defaultSubmitPageUrl = "/login/ott";
        private String tokenGeneratingUrl = "/ott/generate";
        private boolean showDefaultSubmitPage = true;
        private OneTimeTokenService tokenService;
        private OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;
        private Customizer<OneTimeTokenLoginConfigurer<HttpSecurity>> rawOttLogin;

        @Override
        protected Builder self() {
            return this;
        }

        public Builder matchers(List<String> patterns) {
            this.matchers = Objects.requireNonNull(patterns, "matchers must not be null");
            return this;
        }

        public Builder loginProcessingUrl(String url) {
            this.loginProcessingUrl = Objects.requireNonNull(url, "loginProcessingUrl must not be null");
            return this;
        }

        public Builder defaultSubmitPageUrl(String url) {
            this.defaultSubmitPageUrl = Objects.requireNonNull(url, "defaultSubmitPageUrl must not be null");
            return this;
        }

        public Builder tokenGeneratingUrl(String url) {
            this.tokenGeneratingUrl = Objects.requireNonNull(url, "tokenGeneratingUrl must not be null");
            return this;
        }

        public Builder showDefaultSubmitPage(boolean show) {
            this.showDefaultSubmitPage = show;
            return this;
        }

        public Builder tokenService(OneTimeTokenService service) {
            this.tokenService = Objects.requireNonNull(service, "tokenService must not be null");
            return this;
        }

        public Builder tokenGenerationSuccessHandler(OneTimeTokenGenerationSuccessHandler handler) {
            this.tokenGenerationSuccessHandler = Objects.requireNonNull(handler, "tokenGenerationSuccessHandler must not be null");
            return this;
        }

        public Builder rawFormLogin(Customizer<OneTimeTokenLoginConfigurer<HttpSecurity>> c) {
            this.rawOttLogin = Objects.requireNonNull(c, "rawFormLogin customizer must not be null");
            return self();
        }

        @Override
        public OttOptions build() {
            if (matchers.isEmpty()) {
                throw new IllegalStateException("At least one matcher is required");
            }
            // 기본 tokenService 설정
            if (tokenService == null) {
                tokenService = new InMemoryOneTimeTokenService();
            }
            return new OttOptions(this);
        }
    }
}
