package io.springsecurity.springsecurity6x.security.factory;

import io.springsecurity.springsecurity6x.security.expression.ExpressionEvaluator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * ExpressionEvaluator 전략들을 사용하여, 주어진 표현식에 가장 적합한
 * Spring Security의 AuthorizationManager를 해석(resolve)하고 반환한다.
 */
@Component
@RequiredArgsConstructor
public class ExpressionAuthorizationManagerResolver {

    // Spring이 모든 ExpressionEvaluator 빈을 자동으로 주입 (List<ExpressionEvaluator>)
    private final List<ExpressionEvaluator> evaluators;

    public AuthorizationManager<RequestAuthorizationContext> resolve(String expression) {
        for (ExpressionEvaluator evaluator : evaluators) {
            if (evaluator.supports(expression)) {
                return evaluator.createManager(expression);
            }
        }
        // WebSpelExpressionEvaluator가 @Order에 의해 항상 마지막에 위치하고,
        // supports가 true를 반환하므로 이 예외는 발생하지 않음.
        throw new IllegalArgumentException("No evaluator found for expression: " + expression);
    }
}