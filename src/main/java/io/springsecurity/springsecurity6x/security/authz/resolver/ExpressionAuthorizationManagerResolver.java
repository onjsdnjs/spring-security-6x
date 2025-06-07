package io.springsecurity.springsecurity6x.security.authz.resolver;

import io.springsecurity.springsecurity6x.security.authz.risk.RiskEngine;
import io.springsecurity.springsecurity6x.security.authz.expression.ExpressionEvaluator;
import io.springsecurity.springsecurity6x.security.authz.expression.WebSpelExpressionEvaluator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class ExpressionAuthorizationManagerResolver {

    private final List<ExpressionEvaluator> evaluators;
    private final RiskEngine riskEngine; // <<< RiskEngine 주입

    public AuthorizationManager<RequestAuthorizationContext> resolve(String expression) {
        for (ExpressionEvaluator evaluator : evaluators) {
            if (evaluator.supports(expression)) {

                // <<< 핵심 개선: WebExpressionAuthorizationManager 생성 시 리스크 점수를 주입하도록 변경 >>>
                if (evaluator instanceof WebSpelExpressionEvaluator) {
                    WebExpressionAuthorizationManager manager = new WebExpressionAuthorizationManager(expression);

                    // DefaultWebSecurityExpressionHandler를 커스터마이징하여 RiskEngine을 설정
                    DefaultWebSecurityExpressionHandler expressionHandler = new DefaultWebSecurityExpressionHandler();
                    expressionHandler.setExpressionParser(((WebSpelExpressionEvaluator)evaluator).getExpressionParser());

                    // 필요 시 RoleHierarchy 등 다른 컴포넌트도 설정 가능
                    // expressionHandler.setRoleHierarchy(...)

                    manager.setExpressionHandler(expressionHandler);
                    return manager;
                }

                return evaluator.createManager(expression);
            }
        }
        throw new IllegalArgumentException("No evaluator found for expression: " + expression);
    }
}