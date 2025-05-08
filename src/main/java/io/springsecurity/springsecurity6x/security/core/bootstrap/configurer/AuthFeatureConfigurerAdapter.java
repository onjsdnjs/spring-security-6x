package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;

import java.util.List;

public class AuthFeatureConfigurerAdapter implements SecurityConfigurer {
    private final AuthenticationFeature feature;
    private final List<AuthenticationStepConfig> steps;

    public AuthFeatureConfigurerAdapter(AuthenticationFeature feature,
                                        List<AuthenticationStepConfig> steps) {
        this.feature = feature;
        this.steps = steps;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) {
        // no-op
    }

    @Override
    public void configure(FlowContext fc) throws Exception {
        if (fc.flow().stepConfigs() == null) return;
        for (AuthenticationStepConfig step : fc.flow().stepConfigs()) {
            if (feature.getId().equalsIgnoreCase(step.type())) {
                feature.apply(fc.http(), List.of(step), fc.flow().stateConfig());
            }
        }
    }

    @Override
    public int getOrder() {
        return 300; // same as StepConfigurer position
    }
}
