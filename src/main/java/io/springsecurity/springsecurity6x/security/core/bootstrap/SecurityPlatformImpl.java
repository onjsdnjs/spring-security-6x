package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.OrderedSecurityFilterChain;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SecurityPlatform 구현체: Global 설정 후, 각 Flow 별로
 * HttpSecurity를 구성하고 SecurityFilterChain을 생성하여 등록합니다.
 */
@Slf4j
public class SecurityPlatformImpl implements SecurityPlatform {
    private final PlatformContext context;
    private final List<SecurityConfigurer> configurers;
    private PlatformConfig config;
    private final AtomicInteger atomicInteger = new AtomicInteger(1);

    public SecurityPlatformImpl(PlatformContext context, List<SecurityConfigurer> configurers) {
        this.context = context;
        this.configurers = configurers;
    }

    @Override
    public void prepareGlobal(PlatformConfig config, List<?> features) {
        this.config = config;
    }

    @Override
    public void initialize() throws Exception {

        List<FlowContext> flowContexts = new ArrayList<>();

        for (AuthenticationFlowConfig flow : config.flows()) {
            HttpSecurity http = context.newHttp();
            context.registerHttp(flow, http);
            flowContexts.add(new FlowContext(flow, http, context, config));
        }

        for (SecurityConfigurer cfg : configurers) {
            cfg.init(context, config);
        }

        for (FlowContext fc : flowContexts) {
            for (SecurityConfigurer cfg : configurers) {
                cfg.configure(fc);
            }
        }

        for (FlowContext fc : flowContexts) {
            DefaultSecurityFilterChain chain = fc.http().build();
            OrderedSecurityFilterChain orderedFilterChain =
                    new OrderedSecurityFilterChain(Ordered.HIGHEST_PRECEDENCE, chain.getRequestMatcher(), chain.getFilters());
            String beanName = fc.flow().typeName() + "SecurityFilterChain" + atomicInteger.getAndIncrement();
            context.registerChain(beanName, orderedFilterChain);
            context.registerAsBean(beanName, orderedFilterChain);
        }
    }
}
