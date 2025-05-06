package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.bootstrap.FeatureRegistry;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;

/**
 * 인증 흐름에 따른 상태(State) 전략을 HTTP 보안에 적용합니다.
 */
public class StateConfigurer implements SecurityConfigurer {
    private final FeatureRegistry registry;
    public StateConfigurer(FeatureRegistry registry) {
        this.registry = registry;
    }

    @Override
    public void configure(PlatformContext ctx, List<AuthenticationFlowConfig> flows) throws Exception {
        for (AuthenticationFlowConfig flow : flows) {
            HttpSecurity http = ctx.http();
            StateFeature sf = registry.getStateFeature(flow.stateConfig().state());
            if (sf != null) {
                sf.apply(http, ctx);
            }
        }
    }
}
