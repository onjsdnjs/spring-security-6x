package io.springsecurity.springsecurity6x.security.core.dsl.mfa;

import jakarta.servlet.http.HttpServletRequest;

/**
 * 로그인 시 요청 컨텍스트를 기반으로 리스크 점수를 평가하는 엔진.
 */
public interface RiskEngine {
    /**
     * @param request 현재 HTTP 요청
     * @return 리스크 평가 결과 (score, highRisk 여부)
     */
    RiskAssessmentResult assess(HttpServletRequest request);
}
