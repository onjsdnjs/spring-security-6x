package io.springsecurity.springsecurity6x.security.core.dsl.mfa;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * MFA 멀티스텝 인증을 오케스트레이션하는 매니저.
 * - DSL로 설정된 retry, adaptive, deviceTrust, recovery 모두 반영
 * - 각 스텝 HTTP→AuthenticationToken 변환 후 AuthenticationManager에 위임
 */
public class MultiFactorManager {
    private final FeatureRegistry registry;
    private final AuditEventPublisher auditPublisher;
    private final AuthenticationManager authenticationManager;
    private final RiskEngine riskEngine;
    private final TrustedDeviceService trustedDeviceService;
    private final RecoveryService recoveryService;

    public MultiFactorManager(FeatureRegistry registry,
                              AuditEventPublisher auditPublisher,
                              AuthenticationManager authenticationManager,
                              RiskEngine riskEngine,
                              TrustedDeviceService trustedDeviceService,
                              RecoveryService recoveryService) {
        this.registry = registry;
        this.auditPublisher = auditPublisher;
        this.authenticationManager = authenticationManager;
        this.riskEngine = riskEngine;
        this.trustedDeviceService = trustedDeviceService;
        this.recoveryService = recoveryService;
    }

    /**
     * 멀티스텝 MFA 인증 실행.
     *
     * @throws AuthenticationException 인증 실패 시
     * @throws InterruptedException    retry 시 lockoutSec 만큼 sleep
     */
    public Authentication authenticate(HttpServletRequest req, HttpServletResponse res)
            throws AuthenticationException, InterruptedException, IOException {

        // 1) DSL로 정의된 MFA Flow 조회
        AuthenticationFlowConfig flow = registry.getFlow("mfa");
        List<AuthenticationStepConfig> steps = flow.stepConfigs();

        // 2) DSL로 저장된 설정 꺼내기
        RetryPolicy      retryPolicy    = flow.retryPolicy();
        AdaptiveConfig   adaptiveConfig = flow.adaptiveConfig();
        boolean          deviceTrust    = flow.deviceTrust();
        RecoveryConfig   recoveryConfig = flow.recoveryConfig();

        // 3) Adaptive 평가
        if (adaptiveConfig != null && (adaptiveConfig.geolocation() || adaptiveConfig.devicePosture())) {
            var risk = riskEngine.assess(req);
            if (risk.isHighRisk()) {
                auditPublisher.publish("MFA_ADAPTIVE_TRIGGER", Map.of("riskScore", risk.getScore()));
                // 추가 단계 삽입 또는 사용자 알림 로직 가능
            }
        }

        // 4) Trusted Device 검사
        if (deviceTrust && trustedDeviceService.isTrusted(req)) {
            auditPublisher.publish("MFA_DEVICE_TRUSTED", Map.of("deviceId", trustedDeviceService.getDeviceId(req)));
            // 신뢰된 디바이스인 경우 스텝 전부 스킵하거나 별도 플로우로 분기 가능
        }

        Authentication lastAuth = null;

        // 5) 각 스텝별 인증 실행
        for (int i = 0; i < steps.size(); i++) {
            AuthenticationStepConfig step = steps.get(i);
            FactorAuthenticator converter = registry.getFactorAuthenticator(step.type());

            int attempts = 0;
            while (true) {
                attempts++;
                try {
                    // 5-1) HTTP → AuthenticationToken 변환
                    var token = converter.convert(req, step);

                    // 5-2) Spring Security AuthenticationManager에 위임
                    Authentication auth = authenticationManager.authenticate(token);
                    lastAuth = auth;

                    auditPublisher.publish("MFA_STEP_SUCCESS",
                            Map.of("stepIndex", i, "factorType", step.type()));
                    break;
                } catch (AuthenticationException ex) {
                    auditPublisher.publish("MFA_STEP_FAILURE",
                            Map.of("stepIndex", i,
                                    "factorType", step.type(),
                                    "attempt", attempts,
                                    "reason", ex.getMessage()));

                    // 5-3) Retry 조건 검사
                    if (retryPolicy != null && attempts < retryPolicy.maxAttempts()) {
                        auditPublisher.publish("MFA_STEP_RETRY",
                                Map.of("stepIndex", i, "nextAttempt", attempts + 1));
                        Thread.sleep(retryPolicy.lockoutSec() * 1000L);
                        continue;
                    }

                    // 5-4) Recovery Flow 분기
                    if (recoveryConfig != null) {
                        recoveryService.initiateRecovery(req, res, recoveryConfig);
                        throw new AuthenticationServiceException("Recovery initiated");
                    }

                    // 5-5) 최종 실패
                    throw new BadCredentialsException(
                            "MFA failed at step " + step.type(), ex);
                }
            }
        }

        // 6) 모든 스텝 통과
        if (lastAuth == null) {
            throw new AuthenticationServiceException("No Authentication obtained after MFA");
        }

        auditPublisher.publish("MFA_SUCCESS",
                Map.of("principal", lastAuth.getPrincipal()));
        return lastAuth;
    }
}





