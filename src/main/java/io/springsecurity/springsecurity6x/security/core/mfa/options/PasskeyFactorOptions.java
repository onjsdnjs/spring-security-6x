package io.springsecurity.springsecurity6x.security.core.mfa.options;

import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.util.Assert;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class PasskeyFactorOptions extends FactorAuthenticationOptions {
    private final String rpName;
    private final String rpId;
    private final Set<String> allowedOrigins;

    private PasskeyFactorOptions(Builder builder) {
        super(builder, AuthType.PASSKEY); // 수정된 부모 생성자 호출
        this.rpName = builder.rpName;
        this.rpId = builder.rpId;
        this.allowedOrigins = Collections.unmodifiableSet(new HashSet<>(builder.allowedOrigins));
    }

    public String getRpName() { return rpName; }
    public String getRpId() { return rpId; }
    public Set<String> getAllowedOrigins() { return allowedOrigins; }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends FactorAuthenticationOptions.AbstractFactorOptionsBuilder<PasskeyFactorOptions, Builder> {
        private String rpName = "My Application";
        private String rpId;
        private Set<String> allowedOrigins = new HashSet<>();

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

        public Builder allowedOrigins(Set<String> allowedOrigins) {
            Assert.notEmpty(allowedOrigins, "allowedOrigins cannot be empty");
            this.allowedOrigins = allowedOrigins;
            return this;
        }

        @Override
        protected Builder self() {
            return this;
        }

        @Override
        public PasskeyFactorOptions build() {
            Assert.hasText(super.processingUrl, "Processing URL must be set for Passkey factor.");
            Assert.hasText(this.rpId, "RP ID (rpId) must be configured for Passkey factor.");
            Assert.notEmpty(this.allowedOrigins, "Allowed origins must be configured for Passkey factor.");
            return new PasskeyFactorOptions(this);
        }
    }
}