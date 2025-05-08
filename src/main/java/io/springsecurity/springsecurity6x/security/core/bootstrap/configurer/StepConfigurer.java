package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;

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
    public void init(PlatformContext ctx, PlatformConfig config) { }

    @Override
    public void configure(FlowContext ctx) throws Exception {
        List<AuthenticationStepConfig> steps = ctx.flow().stepConfigs();
        if (steps == null || steps.isEmpty()) {
            return;
        }
        for (AuthenticationStepConfig step : steps) {
            AuthenticationFeature f = registry.getAuthFeature(step.type());
            if (f == null) {
                throw new IllegalStateException("No feature for step type: " + step.type());
            }
            f.apply(ctx.http(), List.of(step), ctx.flow().stateConfig());
        }
    }

    @Override
    public int getOrder() { return 300; }
}

