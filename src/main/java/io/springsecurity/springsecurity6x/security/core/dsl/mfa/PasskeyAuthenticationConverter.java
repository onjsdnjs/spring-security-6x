package io.springsecurity.springsecurity6x.security.core.dsl.mfa;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication;

public class PasskeyAuthenticationConverter implements FactorAuthenticator {

    @Override
    public Authentication convert(HttpServletRequest request,
                                  AuthenticationStepConfig step)
            throws AuthenticationException {
        WebAuthnAuthentication token =
                WebAuthnCredentialsConverter.fromRequest(request);
        if (token == null) {
            throw new InsufficientAuthenticationException("Missing passkey credentials");
        }
        return token;
    }
}
