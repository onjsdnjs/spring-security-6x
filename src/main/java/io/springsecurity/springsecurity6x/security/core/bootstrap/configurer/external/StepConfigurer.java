package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.external;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
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
    public void init(PlatformContext ctx, PlatformConfig config) throws Exception {

    }

    @Override
    public void configure(FlowContext ctx) throws Exception {
        AuthenticationFlowConfig flow = ctx.flow();
        HttpSecurity http = ctx.http();
        for (AuthenticationStepConfig step : flow.stepConfigs()) {
            AuthenticationFeature f = registry.getAuthFeature(step.type());
            if (f == null) {
                throw new IllegalStateException("No feature for step type: " + step.type());
            }
            f.apply(http, List.of(step), flow.stateConfig());
        }
    }

    @Override
    public int getOrder() {
        return SecurityConfigurer.super.getOrder();
    }
}
