package io.springsecurity.springsecurity6x.security.core.mfa;

import jakarta.servlet.Filter;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;

import java.util.HashMap;
import java.util.Map;

public class MfaFactorHandlerRegistry {
    private final Map<String, Filter> filters = new HashMap<>();

    public MfaFactorHandlerRegistry(UsernamePasswordAuthenticationFilter restFilter,
                                    AuthenticationFilter ottFilter, WebAuthnAuthenticationFilter passkeyFilter) {
        filters.put("rest", restFilter);
        filters.put("ott", ottFilter);
        filters.put("passkey", passkeyFilter);
    }

    public Filter getFilter(String factorType) {
        return filters.get(factorType);
    }
}

