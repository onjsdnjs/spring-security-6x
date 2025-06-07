package io.springsecurity.springsecurity6x.security.authz.expression;

import io.springsecurity.springsecurity6x.security.authz.risk.RiskEngine;
import lombok.RequiredArgsConstructor;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation; // <<< Supplier, RequestAuthorizationContext 대신 FilterInvocation 사용
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.stereotype.Component;

/**
 * 기본 SecurityExpressionHandler를 확장하여, SpEL 평가 컨텍스트에
 * 동적인 값(#riskScore 등)을 추가하는 책임을 갖는다.
 */
@Component
@RequiredArgsConstructor
public class CustomWebSecurityExpressionHandler extends DefaultWebSecurityExpressionHandler {

    private final RiskEngine riskEngine;

    /**
     * <<< 핵심 수정: 올바른 메서드 시그니처로 오버라이드 >>>
     * 이 메서드는 WebExpressionAuthorizationManager가 내부적으로 SpEL을 평가하기 직전에 호출됩니다.
     * @param authentication 현재 인증 객체
     * @param invocation 현재 요청에 대한 FilterInvocation (request, response 포함)
     * @return 커스터마이징된 EvaluationContext
     */
    @Override
    protected StandardEvaluationContext createEvaluationContext(Authentication authentication, FilterInvocation invocation) {
        // 1. 부모 클래스의 메서드를 호출하여 기본적인 SpEL 컨텍스트(#auth, #request 등)를 생성합니다.
        StandardEvaluationContext context = super.createEvaluationContext(authentication, invocation);

        // 2. FilterInvocation에서 HttpServletRequest를 안전하게 추출합니다.
        // FilterInvocation getRequest() is guaranteed to return an HttpServletRequest.
        var request = invocation.getRequest();

        // 3. RiskEngine을 통해 리스크 점수를 계산하고 SpEL 컨텍스트에 '#riskScore' 변수로 주입합니다.
        int riskScore = riskEngine.calculateRiskScore(authentication, request);
        context.setVariable("riskScore", riskScore);

        return context;
    }
}