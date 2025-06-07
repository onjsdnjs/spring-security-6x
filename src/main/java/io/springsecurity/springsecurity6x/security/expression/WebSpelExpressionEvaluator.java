package io.springsecurity.springsecurity6x.security.expression;

import org.springframework.core.annotation.Order;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

@Component
@Order // 가장 마지막에 실행되도록 Order 설정
public class WebSpelExpressionEvaluator implements ExpressionEvaluator {
    @Override
    public boolean supports(String expression) {
        // 다른 평가기에서 처리하지 못한 모든 표현식을 지원 (Fallback 역할)
        return true;
    }

    @Override
    public AuthorizationManager<RequestAuthorizationContext> createManager(String expression) {
        return new WebExpressionAuthorizationManager(expression);
    }
}