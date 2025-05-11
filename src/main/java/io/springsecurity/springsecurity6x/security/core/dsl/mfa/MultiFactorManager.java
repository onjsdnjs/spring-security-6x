package io.springsecurity.springsecurity6x.security.core.dsl.mfa;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Map;


public class MultiFactorManager {
    private final FeatureRegistry registry;
    private final AuditEventPublisher auditPublisher;
    private final AuthenticationManager authenticationManager;

    public MultiFactorManager(FeatureRegistry registry,
                              AuditEventPublisher auditPublisher,
                              AuthenticationManager authenticationManager) {
        this.registry = registry;
        this.auditPublisher = auditPublisher;
        this.authenticationManager = authenticationManager;
    }

    public Authentication authenticate(HttpServletRequest req, HttpServletResponse res) {

        AuthenticationFlowConfig flow = registry.getFlow("mfa");
        List<AuthenticationStepConfig> steps = flow.stepConfigs();
        Authentication lastAuth = null;

        for (int i = 0; i < steps.size(); i++) {
            AuthenticationStepConfig step = steps.get(i);
            FactorAuthenticator converter = registry.getFactorAuthenticator(step.type());

            auditPublisher.publish("MFA_STEP_START",
                    Map.of("step", i, "type", step.type()));

            // 1) 요청 → AuthenticationToken 변환
            var token = converter.convert(req, step);

            // 2) Spring Security 인증 매니저 호출
            Authentication auth = authenticationManager.authenticate(token);

            lastAuth = auth;
            auditPublisher.publish("MFA_STEP_SUCCESS", Map.of("step", i, "type", step.type()));
        }

        if (lastAuth == null) {
            throw new AuthenticationServiceException("No MFA steps executed");
        }

        auditPublisher.publish("MFA_SUCCESS", Map.of("principal", lastAuth.getPrincipal()));
        return lastAuth;
    }
}




