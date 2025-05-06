package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.*;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * SecurityPlatform 구현체: Global 설정 후, 각 Flow별로
 * HttpSecurity를 구성하고 SecurityFilterChain을 생성하여 등록합니다.
 */
/**
 * 분리된 Configurer들을 이용해 보안 체인을 구성합니다.
 */
@Component
public class SecurityPlatformImpl implements SecurityPlatform {
    private final PlatformContext context;
    private final FeatureRegistry registry;
    private final List<SecurityConfigurer> configurers;
    private PlatformConfig config;

    public SecurityPlatformImpl(PlatformContext context, FeatureRegistry registry) {
        this.context = context;
        this.registry = registry;
        this.configurers = List.of(
                new GlobalConfigurer(),
                new FlowConfigurer(),
                new StateConfigurer(registry),
                new StepConfigurer(registry)
        );
    }

    @Override
    public void prepareGlobal(PlatformConfig config, List<?> features) {
        this.config = config;
    }

    @Override
    public void initialize() throws Exception {
        // init & configure
        for (SecurityConfigurer cfg : configurers) {
            cfg.init(context, config);
            cfg.configure(context, config.getFlows());
        }
        // performBuild
        for (AuthenticationFlowConfig flow : config.getFlows()) {
            SecurityFilterChain chain = context.getHttp().build();
            context.registerChain(flow.getTypeName(), chain);
        }
    }
}
