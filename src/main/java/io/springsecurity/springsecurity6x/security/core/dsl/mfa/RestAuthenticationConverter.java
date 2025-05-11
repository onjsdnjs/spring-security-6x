package io.springsecurity.springsecurity6x.security.core.dsl.mfa;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;

public class RestAuthenticationConverter implements FactorAuthenticator {

    private final String usernameParam;
    private final String passwordParam;

    public RestAuthenticationConverter(String userParam, String passParam) {
        this.usernameParam = userParam;
        this.passwordParam = passParam;
    }

    @Override
    public UsernamePasswordAuthenticationToken convert(HttpServletRequest request,
                                                       AuthenticationStepConfig step)
            throws AuthenticationException {
        String user = request.getParameter(usernameParam);
        String pass = request.getParameter(passwordParam);
        if (user == null || pass == null) {
            throw new InsufficientAuthenticationException("Missing credentials");
        }
        return new UsernamePasswordAuthenticationToken(user, pass);
    }
}