package io.springsecurity.springsecurity6x.security.authz.expression;

import io.springsecurity.springsecurity6x.security.authz.context.AuthorizationContext;
import io.springsecurity.springsecurity6x.security.authz.context.ContextHandler;
import io.springsecurity.springsecurity6x.security.authz.pip.AttributeInformationPoint;
import io.springsecurity.springsecurity6x.security.authz.risk.RiskEngine;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomWebSecurityExpressionHandler extends DefaultWebSecurityExpressionHandler {

    private final RiskEngine riskEngine;
    private final ContextHandler contextHandler;
    private final AttributeInformationPoint attributePIP;

    @Override
    protected SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, FilterInvocation fi) {
        // <<< 1. ContextHandler를 통해 표준 AuthorizationContext 생성 >>>
        AuthorizationContext authzContext = contextHandler.create(authentication, fi.getRequest());

        // <<< 2. 커스텀 Root 객체 생성 시, 표준 컨텍스트와 PIP를 함께 전달 >>>
        CustomWebSecurityExpressionRoot root = new CustomWebSecurityExpressionRoot(authentication, fi, riskEngine, attributePIP, authzContext);

        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(new AuthenticationTrustResolverImpl());
        root.setRoleHierarchy(getRoleHierarchy());
        root.setDefaultRolePrefix("ROLE_");

        return root;
    }
}