package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.config.StateConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;

/**
 * 인증 흐름에 따른 상태(State) 전략을 HTTP 보안에 적용합니다.
 */
public class StateConfigurer implements SecurityConfigurer {
    private final FeatureRegistry registry;
    public StateConfigurer(FeatureRegistry registry) {
        this.registry = registry;
    }

    @Override
    public void init(PlatformContext ctx, PlatformConfig config) { }

    @Override
    public void configure(FlowContext ctx) throws Exception {
        StateConfig state = ctx.flow().stateConfig();
        if (state == null) {
            return;
        }
        StateFeature sf = registry.getStateFeature(state.state());
        if (sf != null) {
            sf.apply(ctx.http(), ctx.context());
        }
    }

    @Override
    public int getOrder() { return 400; }
}

