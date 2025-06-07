package io.springsecurity.springsecurity6x.security.authz.risk;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class DefaultRiskEngine implements RiskEngine {

    // 실제 운영 환경에서는 DB나 외부 시스템에서 관리되어야 합니다.
    private static final Set<String> TRUSTED_IPS = Set.of("127.0.0.1", "0:0:0:0:0:0:0:1");

    @Override
    public int calculateRiskScore(Authentication authentication, HttpServletRequest request) {
        String remoteIp = request.getRemoteAddr();

        // 신뢰된 IP 에서 온 요청은 낮은 위험도(10)를 가집니다.
        if (TRUSTED_IPS.contains(remoteIp)) {
            return 10;
        }

        // 그 외의 경우는 중간 수준의 위험도(50)를 가집니다.
        // 향후: 로그인 시간, 사용자 에이전트, 이전 로그인 기록 등을 분석하여 점수를 동적으로 계산
        return 50;
    }
}
