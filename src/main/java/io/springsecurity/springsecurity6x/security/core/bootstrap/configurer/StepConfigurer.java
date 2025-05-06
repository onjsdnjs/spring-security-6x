package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

/**
 * 각 인증 단계(Step)를 HTTP 보안에 적용합니다.
 */
public class StepConfigurer implements SecurityConfigurer {
    private final FeatureRegistry registry;
    public StepConfigurer(FeatureRegistry registry) {
        this.registry = registry;
    }

    @Override
    public void configure(PlatformContext ctx, List<AuthenticationFlowConfig> flows) throws Exception {
        for (AuthenticationFlowConfig flow : flows) {
            HttpSecurity http = ctx.getHttp();
            for (AuthenticationStepConfig step : flow.getStepConfigs()) {
                if (step.getMatchers() != null) {
                    http = http.securityMatcher(step.getMatchers());
                }
                AuthenticationFeature f = registry.getAuthFeature(step.getType());
                if (f == null) {
                    throw new IllegalStateException("No feature for step type: " + step.getType());
                }
                f.apply(http, List.of(step), flow.getStateConfig());
            }
        }
    }
}
