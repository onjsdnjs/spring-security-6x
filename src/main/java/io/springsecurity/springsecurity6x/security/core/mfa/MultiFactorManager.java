package io.springsecurity.springsecurity6x.security.core.mfa;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

/**
 * Spring Security 제공 필터들을 순차 호출해서 MFA를 수행하는 매니저.
 */
public class MultiFactorManager {
    private final FeatureRegistry registry;
    private final AuditEventPublisher auditPublisher;
    private final RiskEngine riskEngine;
    private final TrustedDeviceService trustedDeviceService;
    private final RecoveryService recoveryService;

    /**
     * @param registry               step별로 매핑된 인증 필터를 꺼내는 레지스트리
     * @param auditPublisher         이벤트 로깅용 퍼블리셔
     * @param riskEngine             Adaptive 평가 엔진
     * @param trustedDeviceService   DeviceTrust 검사 서비스
     * @param recoveryService        Recovery 워크플로우 서비스
     */
    public MultiFactorManager(FeatureRegistry registry,
                              AuditEventPublisher auditPublisher,
                              RiskEngine riskEngine,
                              TrustedDeviceService trustedDeviceService,
                              RecoveryService recoveryService) {
        this.registry = registry;
        this.auditPublisher = auditPublisher;
        this.riskEngine = riskEngine;
        this.trustedDeviceService = trustedDeviceService;
        this.recoveryService = recoveryService;
    }

    /**
     * 순차적으로 Spring Security의 기존 필터를 호출하여 MFA를 실행합니다.
     */
    public Authentication authenticate(HttpServletRequest req, HttpServletResponse res)
            throws AuthenticationException, IOException, ServletException, InterruptedException {

        AuthenticationFlowConfig flow = registry.getFlow("mfa");
        List<AuthenticationStepConfig> steps = flow.stepConfigs();

        RetryPolicy    retryPolicy    = flow.retryPolicy();
        AdaptiveConfig adaptiveConfig = flow.adaptiveConfig();
        boolean        deviceTrust    = flow.deviceTrust();
        RecoveryConfig recoveryConfig = flow.recoveryConfig();

        // (1) Adaptive 검사
        if (adaptiveConfig != null &&
                (adaptiveConfig.geolocation() || adaptiveConfig.devicePosture())) {
            var risk = riskEngine.assess(req);
            if (risk.isHighRisk()) {
                auditPublisher.publish("MFA_ADAPTIVE_TRIGGER", Map.of("score", risk.getScore()));
            }
        }

        // (2) Device Trust 검사
        if (deviceTrust && trustedDeviceService.isTrusted(req)) {
            auditPublisher.publish("MFA_DEVICE_TRUSTED",
                    Map.of("deviceId", trustedDeviceService.getDeviceId(req)));
            // 스텝 모두 스킵하고 바로 리턴 처리해도 되고, 계속해서 스텝 실행해도 됩니다.
        }

        Authentication lastAuth = null;

        // (3) Step별로 기존 필터 호출
        for (int i = 0; i < steps.size(); i++) {
            AuthenticationStepConfig step = steps.get(i);

            // 레지스트리에서 step.type()에 해당하는 필터를 꺼냄
            AbstractAuthenticationProcessingFilter filter = registry.getFactorFilter(step.getType());

            if (filter == null) {
                throw new IllegalStateException("No filter registered for MFA factor: " + step.type());
            }

            int attempts = 0;
            while (true) {
                attempts++;
                try {
                    auditPublisher.publish("MFA_STEP_START",
                            Map.of("stepIndex", i, "factorType", step.type()));

                    // 핵심: Filter의 attemptAuthentication 호출
                    Authentication auth = filter.attemptAuthentication(req, res);
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

                    // Retry 로직
                    if (retryPolicy != null && attempts < retryPolicy.maxAttempts()) {
                        auditPublisher.publish("MFA_STEP_RETRY",
                                Map.of("stepIndex", i, "nextAttempt", attempts + 1));
                        Thread.sleep(retryPolicy.lockoutSec() * 1000L);
                        continue;
                    }

                    // Recovery 분기
                    if (recoveryConfig != null) {
                        recoveryService.initiateRecovery(req, res, recoveryConfig);
                        throw new AuthenticationServiceException("Recovery initiated");
                    }

                    // 최종 실패
                    throw new BadCredentialsException(
                            "MFA failed at step " + step.type(), ex);
                }
            }
        }

        // (4) 전체 통과 후 성공 이벤트
        if (lastAuth == null) {
            throw new AuthenticationServiceException("No authentication after MFA");
        }
        auditPublisher.publish("MFA_SUCCESS",
                Map.of("principal", lastAuth.getPrincipal()));
        return lastAuth;
    }
}






