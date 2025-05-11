package io.springsecurity.springsecurity6x.security.filter;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.mfa.*;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * MFA 진입점이 되는 Filter.
 *  - "/api/auth/mfa" 같은 단일 엔드포인트만 매칭
 *  - 내부적으로 각 Flow별 SecurityFilterChain 을 꺼내 인증용 Filter만 순차 doFilter() 호출
 */
public class MfaAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private final FeatureRegistry registry;
    private final AuditEventPublisher auditPublisher;
    private final RiskEngine riskEngine;
    private final TrustedDeviceService trustedDeviceService;
    private final RecoveryService recoveryService;

    public MfaAuthenticationFilter(String mfaEndpoint,
                                   FeatureRegistry registry,
                                   AuditEventPublisher auditPublisher,
                                   RiskEngine riskEngine,
                                   TrustedDeviceService trustedDeviceService,
                                   RecoveryService recoveryService) {
        super(mfaEndpoint);
        this.registry               = registry;
        this.auditPublisher         = auditPublisher;
        this.riskEngine             = riskEngine;
        this.trustedDeviceService   = trustedDeviceService;
        this.recoveryService        = recoveryService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        AuthenticationFlowConfig flow = registry.getFlow("mfa");
        List<AuthenticationStepConfig> steps   = flow.stepConfigs();
        RetryPolicy retry   =       flow.retryPolicy();
        AdaptiveConfig               adaptive = flow.adaptiveConfig();
        boolean                      device   = flow.deviceTrust();
        RecoveryConfig              recovery = flow.recoveryConfig();

        if (adaptive != null && (adaptive.geolocation() || adaptive.devicePosture())) {
            var risk = riskEngine.assess(request);
            if (risk.isHighRisk()) {
                auditPublisher.publish("MFA_ADAPTIVE_TRIGGER", Map.of("risk", risk.getScore()));
            }
        }

        if (device && trustedDeviceService.isTrusted(request)) {
            auditPublisher.publish("MFA_DEVICE_TRUSTED",
                    Map.of("deviceId", trustedDeviceService.getDeviceId(request)));
        }

        Authentication lastAuth = null;
        for (int idx = 0; idx < steps.size(); idx++) {
            AuthenticationStepConfig step = steps.get(idx);
            Filter filter = registry.getFactorFilter(step.type());
            if (filter == null) {
                throw new IllegalStateException("No filter registered for MFA factor: " + step.type());
            }
            int attempts = 0;
            while (true) {
                attempts++;
                try {
                    auditPublisher.publish("MFA_STEP_START", Map.of("step", idx, "type", step.type()));
                    filter.doFilter(request, response, new NoOpFilterChain());
                    lastAuth = SecurityContextHolder.getContext().getAuthentication();
                    if (lastAuth == null) {
                        throw new AuthenticationServiceException("Filter did not populate Authentication for step " + step.type());
                    }
                    auditPublisher.publish("MFA_STEP_SUCCESS", Map.of("step", idx, "type", step.type()));
                    break;

                } catch (AuthenticationException ex) {
                    auditPublisher.publish("MFA_STEP_FAILURE",
                            Map.of("step", idx,
                                    "type", step.type(),
                                    "attempt", attempts,
                                    "reason", ex.getMessage()));

                    if (retry != null && attempts < retry.maxAttempts()) {
                        auditPublisher.publish("MFA_STEP_RETRY",
                                Map.of("step", idx, "nextAttempt", attempts + 1));
//                        Thread.sleep(retry.lockoutSec() * 1000L);
                        continue;
                    }

                    if (recovery != null) {
                        recoveryService.initiateRecovery(request, response, recovery);
                        throw new AuthenticationServiceException("Recovery initiated");
                    }

                    throw new BadCredentialsException(
                            "MFA failed at step " + step.type(), ex);
                }
            }
        }

        if (lastAuth == null) {
            throw new AuthenticationServiceException("No Authentication after MFA");
        }

        auditPublisher.publish("MFA_SUCCESS", Map.of("principal", lastAuth.getPrincipal()));
        return lastAuth;
    }

    /** doFilter 호출용 No-Op 체인 */
    private static class NoOpFilterChain implements FilterChain {
        @Override
        public void doFilter(ServletRequest req, ServletResponse res) {
            // 다음 필터로 넘기지 않습니다.
        }
    }
}

