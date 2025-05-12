package io.springsecurity.springsecurity6x.security.core.mfa.context;

import org.springframework.security.core.Authentication;

// 인증 컨텍스트: 현재 단계 인덱스, 마지막 Authentication 저장
public class FactorContext {
    private int currentStep;
    private Authentication lastAuth;
    // 추가: 실패 카운트, 타임스탬프, 사용자식별자 등

    public int getCurrentStep() { return currentStep; }
    public void advanceStep() { this.currentStep++; }
    public void setCurrentStep(int idx) { this.currentStep = idx; }

    public Authentication getLastAuth() { return lastAuth; }
    public void setLastAuth(Authentication auth) { this.lastAuth = auth; }
}

