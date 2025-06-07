package io.springsecurity.springsecurity6x.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class DefaultRiskEngine implements RiskEngine {
    @Override
    public int calculateRiskScore(Authentication authentication, HttpServletRequest request) {
        // 초기 구현: 로컬호스트 접근은 리스크 0, 그 외에는 30점 부여
        String remoteAddr = request.getRemoteAddr();
        if ("127.0.0.1".equals(remoteAddr) || "0:0:0:0:0:0:0:1".equals(remoteAddr)) {
            return 0; // Low Risk
        }
        return 30; // Medium Risk
    }
}
