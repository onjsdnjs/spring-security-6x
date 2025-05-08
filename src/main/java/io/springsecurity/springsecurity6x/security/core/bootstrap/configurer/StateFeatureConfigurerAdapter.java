package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;

public class StateFeatureConfigurerAdapter implements SecurityConfigurer {
    private final StateFeature feature;
    private final PlatformContext ctx;

    public StateFeatureConfigurerAdapter(StateFeature feature, PlatformContext ctx) {
        this.feature = feature;
        this.ctx = ctx;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) { }

    @Override
    public void configure(FlowContext fc) throws Exception {
        StateConfig state = fc.flow().stateConfig();
        if (state != null && feature.getId().equalsIgnoreCase(state.state())) {
            feature.apply(fc.http(), ctx);
        }
    }

    @Override
    public int getOrder() {
        return 400;
    }
}
