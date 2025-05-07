package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.*;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.OrderedSecurityFilterChain;
import io.springsecurity.springsecurity6x.security.core.context.DefaultPlatformContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

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
    private final SecretKey secretKey;
    private final AuthContextProperties properties;
    private PlatformConfig config;
    private AtomicInteger atomicInteger = new AtomicInteger(1);

    public SecurityPlatformImpl(DefaultPlatformContext context, FeatureRegistry registry, SecretKey secretKey, AuthContextProperties properties) {
        this.context = context;
        this.registry = registry;
        this.secretKey = secretKey;
        this.properties = properties;
        this.configurers = List.of(
                new GlobalConfigurer(),
                new FlowConfigurer(),
                new StateConfigurer(registry),
                new StepConfigurer(registry)
        );
        context.share(SecretKey.class, this.secretKey);
        context.share(AuthContextProperties.class, this.properties);
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
            flowContexts.add(new FlowContext(flow, http, context));
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
