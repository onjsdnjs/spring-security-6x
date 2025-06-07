package io.springsecurity.springsecurity6x.security.authz.expression;

import io.springsecurity.springsecurity6x.security.authz.risk.RiskEngine;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.stereotype.Component;

/**
 * 커스텀 SpEL Root 객체인 CustomWebSecurityExpressionRoot를 생성하는 책임을 갖는다.
 * 이것이 스프링 시큐리티가 의도한 공식적인 확장 포인트이다.
 */
@Component
@RequiredArgsConstructor
public class CustomWebSecurityExpressionHandler extends DefaultWebSecurityExpressionHandler {

    private final RiskEngine riskEngine;

    /**
     * <<< 핵심 수정: 올바른 확장 포인트인 createSecurityExpressionRoot 메서드를 오버라이드 >>>
     */
    @Override
    protected SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication, FilterInvocation fi) {
        // 1. 우리가 만든 커스텀 Root 객체를 생성한다.
        CustomWebSecurityExpressionRoot root = new CustomWebSecurityExpressionRoot(authentication, fi, this.riskEngine);

        // 2. 부모 클래스가 하던 것처럼 필수 컴포넌트(PermissionEvaluator, RoleHierarchy 등)를 설정해준다.
        root.setPermissionEvaluator(getPermissionEvaluator());
        root.setTrustResolver(new AuthenticationTrustResolverImpl());
        root.setRoleHierarchy(getRoleHierarchy());
        root.setDefaultRolePrefix("ROLE_");

        return root;
    }
}