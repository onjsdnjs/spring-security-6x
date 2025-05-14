package io.springsecurity.springsecurity6x.security.core.dsl.option;

import io.springsecurity.springsecurity6x.security.core.mfa.options.FactorAuthenticationOptions;
import lombok.Getter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;

import java.util.*;

@Getter
public final class PasskeyOptions extends FactorAuthenticationOptions {

    private final String assertionOptionsEndpoint;
    private final String rpName;
    private final String rpId;
    private final Set<String> allowedOrigins;
    private final SecurityContextRepository securityContextRepository;

    private PasskeyOptions(Builder builder) {
        super(builder);
        this.assertionOptionsEndpoint = Objects.requireNonNull(builder.assertionOptionsEndpoint, "assertionOptionsEndpoint cannot be null");
        this.rpName = Objects.requireNonNull(builder.rpName, "rpName must not be null");
        this.rpId = Objects.requireNonNull(builder.rpId, "rpId must not be null");
        this.allowedOrigins = builder.allowedOrigins != null ? Collections.unmodifiableSet(new HashSet<>(builder.allowedOrigins)) : Collections.emptySet();
        this.securityContextRepository = builder.securityContextRepository;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends FactorAuthenticationOptions.AbstractFactorOptionsBuilder<PasskeyOptions, Builder> {
        private String assertionOptionsEndpoint = "/webauthn/assertion/options"; // 기본 Assertion Options 요청 URL
        private String rpName = "My Application";
        private String rpId; // 사용자가 반드시 설정
        private List<String> allowedOrigins = new ArrayList<>();
        private SecurityContextRepository securityContextRepository;

        public Builder() {
            super.processingUrl("/login/webauthn"); // Assertion 검증 URL 기본값 설정
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

        @Override
        public PasskeyOptions build() {
            Assert.hasText(rpId, "RP ID (rpId) must be configured for Passkey options.");
            return new PasskeyOptions(this);
        }
    }
}

