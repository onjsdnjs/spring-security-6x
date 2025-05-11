package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.mfa.MultiFactorManager;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * MFA 전용 인증 필터
 */
public class MfaAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final MultiFactorManager manager;

    public MfaAuthenticationFilter(String url,
                                   MultiFactorManager manager,
                                   AuthenticationSuccessHandler successHandler,
                                   AuthenticationFailureHandler failureHandler,
                                   AuthenticationManager authManager) {
        super(url);
        setAuthenticationManager(authManager);
        setAuthenticationSuccessHandler(successHandler);
        setAuthenticationFailureHandler(failureHandler);
        this.manager = manager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) {
        try {
            return manager.authenticate(request, response);
        } catch (Exception ex) {
            throw new AuthenticationServiceException("MFA processing error", ex);
        }
    }
}

