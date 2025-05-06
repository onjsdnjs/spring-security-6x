package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.List;
import java.util.function.Consumer;

/**
 * 각 인증 흐름(Flow) 레벨의 Customizer를 적용합니다.
 */
public class FlowConfigurer implements SecurityConfigurer {
    @Override
    public void configure(PlatformContext ctx, List<AuthenticationFlowConfig> flows) {
        for (AuthenticationFlowConfig flow : flows) {
            Consumer<HttpSecurity> flowCustomizer = flow.getCustomizer();
            if (flowCustomizer != null) {
                flowCustomizer.accept(ctx.getHttp());
            }
        }
    }
}
