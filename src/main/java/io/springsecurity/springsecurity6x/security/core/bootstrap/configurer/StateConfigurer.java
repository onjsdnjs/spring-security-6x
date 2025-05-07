package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * 인증 흐름에 따른 상태(State) 전략을 HTTP 보안에 적용합니다.
 */
public class StateConfigurer implements SecurityConfigurer {
    private final FeatureRegistry registry;
    public StateConfigurer(FeatureRegistry registry) {
        this.registry = registry;
    }

    @Override
    public void configure(FlowContext ctx) throws Exception {
        AuthenticationFlowConfig flow = ctx.flow();
        HttpSecurity http = ctx.http();
        StateFeature sf = registry.getStateFeature(flow.stateConfig().state());
        if (sf != null) {
            sf.apply(http, ctx.context());
        }
    }
}
