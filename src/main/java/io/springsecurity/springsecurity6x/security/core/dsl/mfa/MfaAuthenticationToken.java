package io.springsecurity.springsecurity6x.security.core.dsl.mfa;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * MFA 전용 AuthenticationToken
 */
public class MfaAuthenticationToken extends AbstractAuthenticationToken {
    private final Object principal;

    public MfaAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
