package io.springsecurity.springsecurity6x.security.core.dsl.option;

import lombok.Getter;
import org.springframework.util.Assert;

import java.util.*;

@Getter
public final class PasskeyOptions extends AuthenticationProcessingOptions {

    private final String assertionOptionsEndpoint;
    private final String rpName;
    private final String rpId;
    private final Set<String> allowedOrigins;

    private PasskeyOptions(Builder builder) {
        super(builder);
        this.assertionOptionsEndpoint = builder.assertionOptionsEndpoint;
        this.rpName = builder.rpName;
        this.rpId = builder.rpId;
        this.allowedOrigins = builder.allowedOrigins != null ? Collections.unmodifiableSet(new HashSet<>(builder.allowedOrigins)) : Collections.emptySet();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends AbstractAuthenticationProcessingOptionsBuilder<PasskeyOptions, Builder> {
        private String assertionOptionsEndpoint = "/webauthn/assertion/options";
        private String rpName = "My Application";
        private String rpId;
        private Set<String> allowedOrigins = new HashSet<>(); // Builder에서는 List로 관리

        public Builder() {
            super.loginProcessingUrl("/login/webauthn");
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

        public Builder allowedOrigins(Set<String> origins) {
            this.allowedOrigins = (origins != null) ? origins : new HashSet<>();
            return this;
        }

        public Builder allowedOrigins(List<String> origins) {
            this.allowedOrigins = (origins != null) ? new HashSet<>(origins) : new HashSet<>();
            return this;
        }

        public Builder allowedOrigins(String... origins) {
            this.allowedOrigins = (origins != null) ? new HashSet<>(Arrays.asList(origins)) : new HashSet<>();
            return this;
        }


        @Override
        public PasskeyOptions build() {
            return new PasskeyOptions(this);
        }
    }
}


