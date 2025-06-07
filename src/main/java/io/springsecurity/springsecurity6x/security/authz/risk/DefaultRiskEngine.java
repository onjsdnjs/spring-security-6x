package io.springsecurity.springsecurity6x.security.authz.risk;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.time.LocalTime;
import java.util.Set;

@Service
public class DefaultRiskEngine implements RiskEngine {

    private static final Set<String> TRUSTED_IPS = Set.of("127.0.0.1", "0:0:0:0:0:0:0:1");
    // 업무 시간: 오전 9시 ~ 오후 7시
    private static final LocalTime BUSINESS_HOUR_START = LocalTime.of(9, 0);
    private static final LocalTime BUSINESS_HOUR_END = LocalTime.of(19, 0);

    @Override
    public int calculateRiskScore(Authentication authentication, HttpServletRequest request) {
        int score = 0;

        // 1. IP 기반 평가
        String remoteIp = request.getRemoteAddr();
        if (!TRUSTED_IPS.contains(remoteIp)) {
            score += 30; // 신뢰되지 않은 IP
        }

        // 2. 시간 기반 평가
        LocalTime now = LocalTime.now();
        if (now.isBefore(BUSINESS_HOUR_START) || now.isAfter(BUSINESS_HOUR_END)) {
            score += 20; // 업무 시간 외 접근
        }

        // 3. 관리자 권한에 대한 가중치
        if (authentication != null && authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            score += 10; // ADMIN은 항상 더 높은 주의 필요
        }

        // 향후: UserActivityLogService를 주입받아 과거 이력과 비교하는 로직 추가

        return Math.min(100, score); // 최대 100점
    }
}
