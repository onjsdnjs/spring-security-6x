package io.springsecurity.springsecurity6x.security.core.dsl.option;

import lombok.Getter;
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
@Getter
public final class OttOptions extends AbstractOptions {

    private final List<String> matchers;
    private final String loginProcessingUrl;
    private final String targetUrl;
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
        this.targetUrl = b.targetUrl;
        this.defaultSubmitPageUrl = b.defaultSubmitPageUrl;
        this.tokenGeneratingUrl = b.tokenGeneratingUrl;
        this.showDefaultSubmitPage = b.showDefaultSubmitPage;
        this.tokenService = b.tokenService;
        this.tokenGenerationSuccessHandler = b.tokenGenerationSuccessHandler;
        this.rawOttLogin = b.rawOttLogin;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends AbstractOptions.Builder<OttOptions, Builder> {
        private List<String> matchers = List.of("/**");
        private String loginProcessingUrl = "/login/ott";
        private String targetUrl = "";
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

        public Builder loginProcessingUrl(String url) {
            this.loginProcessingUrl = Objects.requireNonNull(url, "loginProcessingUrl must not be null");
            return this;
        }

        public Builder targetUrl(String u) {
            this.targetUrl = Objects.requireNonNull(u, "targetUrl must not be null");
            return self();
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
