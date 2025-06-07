package io.springsecurity.springsecurity6x.security.authz.expression;

import io.springsecurity.springsecurity6x.security.authz.risk.RiskEngine;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;

/**
 * SpEL 표현식 평가의 루트 객체.
 * 기본 WebSecurityExpressionRoot를 확장하여 커스텀 메서드나 프로퍼티를 추가한다.
 * SpEL에서 'riskScore'와 같이 직접 접근할 수 있다.
 */
public class CustomWebSecurityExpressionRoot extends WebSecurityExpressionRoot {

    private final RiskEngine riskEngine;

    public CustomWebSecurityExpressionRoot(Authentication authentication, FilterInvocation fi, RiskEngine riskEngine) {
        super(authentication, fi);
        this.riskEngine = riskEngine;
    }

    /**
     * SpEL 표현식에서 'riskScore'로 접근할 수 있는 프로퍼티(getter)를 제공한다.
     * 예: @PreAuthorize("hasRole('ADMIN') and riskScore < 70")
     * @return 현재 요청에 대한 위험도 점수
     */
    public int getRiskScore() {
        // 실제 리스크 점수 계산은 RiskEngine에 위임
        return riskEngine.calculateRiskScore(getAuthentication(), this.request);
    }
}