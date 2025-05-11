package io.springsecurity.springsecurity6x.security.core.dsl.mfa;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class OttAuthenticationConverter implements FactorAuthenticator {

    private final String otpParam;

    public OttAuthenticationConverter(String otpParam) {
        this.otpParam = otpParam;
    }

    @Override
    public Authentication convert(HttpServletRequest request,
                                  AuthenticationStepConfig step)
            throws AuthenticationException {
        String otp = request.getParameter(otpParam);
        if (otp == null || otp.isEmpty()) {
            throw new InsufficientAuthenticationException("Missing OTP");
        }
        return new OneTimeTokenAuthenticationToken(otp);
    }
}
