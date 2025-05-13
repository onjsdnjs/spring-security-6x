package io.springsecurity.springsecurity6x.security.core.dsl.option;

import lombok.Getter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Passkey(WebAuthn) 인증 옵션을 immutable으로 제공하는 클래스.
 */
@Getter
public final class PasskeyOptions extends AbstractOptions {

    private final String rpName;
    private final String rpId;
    private final Set<String> allowedOrigins;
    private final String targetUrl;
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;
    private final SecurityContextRepository securityContextRepository;

    private PasskeyOptions(Builder builder) {
        super(builder);
        this.rpName = Objects.requireNonNull(builder.rpName);
        this.rpId = Objects.requireNonNull(builder.rpId);
        this.allowedOrigins = Set.copyOf(builder.allowedOrigins);
        this.targetUrl = builder.targetUrl;
        this.successHandler = builder.successHandler;
        this.failureHandler = builder.failureHandler;
        this.securityContextRepository = builder.securityContextRepository;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends AbstractOptions.Builder<PasskeyOptions, Builder> {
        private List<String> matchers = List.of("/**");
        private String rpName = "SecureApp";
        private String rpId = "localhost";
        private List<String> allowedOrigins = List.of("http://localhost:8080");
        private String targetUrl = "";
        private AuthenticationSuccessHandler successHandler;
        private AuthenticationFailureHandler failureHandler;
        private SecurityContextRepository securityContextRepository;

        @Override
        protected Builder self() {
            return this;
        }

        public Builder rpName(String rpName) {
            this.rpName = Objects.requireNonNull(rpName, "rpName must not be null");
            return this;
        }

        public Builder rpId(String rpId) {
            this.rpId = Objects.requireNonNull(rpId, "rpId must not be null");
            return this;
        }

        public Builder allowedOrigins(List<String> origins) {
            this.allowedOrigins = List.copyOf(Objects.requireNonNull(origins, "allowedOrigins must not be null"));
            return this;
        }

        public Builder targetUrl(String u) {
            this.targetUrl = Objects.requireNonNull(u, "targetUrl must not be null");
            return self();
        }

        public Builder successHandler(AuthenticationSuccessHandler handler) {
            this.successHandler = handler;
            return this;
        }

        public Builder failureHandler(AuthenticationFailureHandler handler) {
            this.failureHandler = handler;
            return this;
        }

        public Builder securityContextRepository(SecurityContextRepository repo) {
            this.securityContextRepository = repo;
            return this;
        }

        @Override
        public PasskeyOptions build() {
            if (matchers == null || matchers.isEmpty()) {
                throw new IllegalStateException("At least one matcher is required");
            }
            return new PasskeyOptions(this);
        }
    }
}


