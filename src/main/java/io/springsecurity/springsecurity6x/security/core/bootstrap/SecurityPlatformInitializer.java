package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.FlowContextFactory;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class SecurityPlatformInitializer implements SecurityPlatform {
    private final PlatformContext context;
    private final PlatformConfig config;
    private final SecurityFilterChainRegistrar registrar;
    private final FlowContextFactory flowContextFactory;
    private final SecurityConfigurerOrchestrator securityConfigurerOrchestrator;

    @Override
    public void prepareGlobal(PlatformConfig config, List<?> features) {
        log.info("SecurityPlatformInitializer: Global preparation with {} features.", features != null ? features.size() : 0);
    }

    @Override
    public void initialize() throws Exception {

        log.info("SecurityPlatformInitializer: Initializing security platform...");
        List<FlowContext> flows = flowContextFactory.createAndSortFlows(config, context);
        context.flowContexts(flows);
        config.setPlatformContext(context);

        if (flows.isEmpty() && !this.config.getFlows().isEmpty()) {
            log.warn("No FlowContexts were created by FlowContextFactory, but PlatformConfig has flows defined. Check FlowContextFactory logic and HttpSecurity provider.");
        }
        securityConfigurerOrchestrator.applyConfigurations(flows, context, config);
        registrar.registerSecurityFilterChains(flows, context.applicationContext());
        log.info("SecurityPlatformInitializer: Security platform initialization complete.");
    }
}

