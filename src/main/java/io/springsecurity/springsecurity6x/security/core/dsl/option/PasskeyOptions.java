package io.springsecurity.springsecurity6x.security.core.dsl.option;

import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import lombok.Getter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;

import java.util.*;

@Getter
public final class PasskeyOptions extends FactorAuthenticationOptions {

    // processingUrl은 FactorAuthenticationOptions의 getProcessingUrl()을 통해 접근 (Assertion 검증/제출 URL)
    private final String assertionOptionsEndpoint; // Assertion Options 요청 URL
    private final String rpName;
    private final String rpId;
    private final Set<String> allowedOrigins;
    // targetUrl, successHandler, failureHandler는 FactorAuthenticationOptions 에서 상속받음
    private final SecurityContextRepository securityContextRepository;

    private PasskeyOptions(Builder builder) {
        super(builder);
        this.assertionOptionsEndpoint = Objects.requireNonNull(builder.assertionOptionsEndpoint, "assertionOptionsEndpoint cannot be null");
        this.rpName = Objects.requireNonNull(builder.rpName, "rpName must not be null");
        this.rpId = Objects.requireNonNull(builder.rpId, "rpId must not be null");
        this.allowedOrigins = builder.allowedOrigins != null ? Collections.unmodifiableSet(new HashSet<>(builder.allowedOrigins)) : Collections.emptySet();
        this.securityContextRepository = builder.securityContextRepository;
    }

    // public String getProcessingUrl() { return super.getProcessingUrl(); } // Assertion 검증/제출 URL

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends FactorAuthenticationOptions.AbstractFactorOptionsBuilder<PasskeyOptions, Builder> {
        private String assertionOptionsEndpoint = "/webauthn/assertion/options";
        private String rpName = "My Application";
        private String rpId;
        private List<String> allowedOrigins = new ArrayList<>();
        private SecurityContextRepository securityContextRepository;

        public Builder() {
            super.processingUrl("/login/webauthn"); // Assertion 검증 URL 기본값
            super.targetUrl("/");
        }

        @Override
        protected Builder self() {
            return this;
        }

        public Builder assertionOptionsEndpoint(String url) {
            Assert.hasText(url, "assertionOptionsEndpoint cannot be empty");
            this.assertionOptionsEndpoint = url;
            return this;
        }

        public Builder rpName(String rpName) {
            Assert.hasText(rpName, "rpName cannot be empty");
            this.rpName = rpName;
            return this;
        }

        public Builder rpId(String rpId) {
            Assert.hasText(rpId, "rpId cannot be empty");
            this.rpId = rpId;
            return this;
        }

        public Builder allowedOrigins(List<String> origins) {
            this.allowedOrigins = (origins != null) ? new ArrayList<>(origins) : new ArrayList<>();
            return this;
        }

        public Builder securityContextRepository(SecurityContextRepository repo) {
            this.securityContextRepository = repo;
            return this;
        }

        // processingUrl, targetUrl, successHandler, failureHandler는 부모 빌더의 메소드 사용

        @Override
        public PasskeyOptions build() {
            Assert.hasText(rpId, "RP ID (rpId) must be configured for Passkey options.");
            return new PasskeyOptions(this);
        }
    }
}


