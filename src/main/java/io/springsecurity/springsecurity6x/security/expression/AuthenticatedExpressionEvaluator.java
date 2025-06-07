package io.springsecurity.springsecurity6x.security.expression;

import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

@Component
public class AuthenticatedExpressionEvaluator implements ExpressionEvaluator {
    @Override
    public boolean supports(String expression) {
        return "isAuthenticated()".equals(expression) || "isFullyAuthenticated()".equals(expression);
    }

    @Override
    public AuthorizationManager<RequestAuthorizationContext> createManager(String expression) {
        if ("isAuthenticated()".equals(expression)) {
            return AuthenticatedAuthorizationManager.authenticated();
        }
        return AuthenticatedAuthorizationManager.fullyAuthenticated();
    }
}