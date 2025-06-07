package io.springsecurity.springsecurity6x.security.authz.risk;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

/**
 * PIP (Policy Information Point)의 한 종류로, 요청의 위험도를 평가하는 책임을 가집니다.
 */
public interface RiskEngine {
    /**
     * 주어진 인증 정보와 요청 컨텍스트를 기반으로 위험도 점수를 계산합니다.
     * @param authentication 현재 인증된 사용자 정보
     * @param request 현재 HTTP 요청
     * @return 위험도 점수 (예: 0-100, 낮을수록 안전)
     */
    int calculateRiskScore(Authentication authentication, HttpServletRequest request);
}
