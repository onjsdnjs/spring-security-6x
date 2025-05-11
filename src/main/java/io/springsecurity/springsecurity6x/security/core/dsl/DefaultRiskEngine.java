package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.mfa.RiskAssessmentResult;
import io.springsecurity.springsecurity6x.security.core.mfa.RiskEngine;
import jakarta.servlet.http.HttpServletRequest;

/**
 * RiskEngine 기본 구현체.
 * 예제에서는 항상 low-risk(0점)로 반환하지만,
 * 실제로는 IP, 디바이스, 시간대, 행동 분석 등을 통해 점수를 계산해야 합니다.
 */
public class DefaultRiskEngine implements RiskEngine {

    @Override
    public RiskAssessmentResult assess(HttpServletRequest request) {
        // 1) 클라이언트 IP 확인
        String ip = extractClientIp(request);

        // 2) 이전 로그인 위치/기록 조회 (DB, Cache 등) — 생략
        //    예: String lastKnownCountry = lookupLastCountryForUser(userId);

        // 3) 간단히 항상 Low Risk 처리
        int score = 0;          // 0 ~ 100 범위의 리스크 점수
        boolean highRisk = false;

        return new RiskAssessmentResult(score, highRisk);
    }

    private String extractClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}
