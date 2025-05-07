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
    private final AtomicInteger chainOrder = new AtomicInteger(1);

    public SecurityPlatformImpl(PlatformContext context,
                                List<SecurityConfigurer> configurers) {
        this.context     = context;
        this.configurers = configurers;
    }

    @Override
    public void prepareGlobal(PlatformConfig config, List<?> features) {
        this.config = config;
    }

    @Override
    public void initialize() throws Exception {

        // 1) FlowContext 준비
        List<FlowContext> flows = createFlowContexts();

        // 2) 전역 초기화(모든 Configurer.init 호출)
        initConfigurers();

        // 3) Flow별 설정(모든 Configurer.configure 호출)
        configureFlows(flows);

        // 4) SecurityFilterChain 생성 및 Bean 등록
        registerSecurityFilterChains(flows);
    }

    private List<FlowContext> createFlowContexts() {

        List<FlowContext> contexts = new ArrayList<>();
        for (AuthenticationFlowConfig flow : config.flows()) {
            try {
                HttpSecurity http = context.newHttp();          // 예외 발생 지점
                context.registerHttp(flow, http);
                FlowContext flowContext = new FlowContext(flow, http, context, config);
                context.share(FlowContext.class, flowContext);
                contexts.add(flowContext);
            } catch (Exception ex) {
                // 예외를 로그에 남기고 해당 플로우는 건너뛸지,
                // 아니면 런타임 예외로 전환해 호출자에게 던질지 결정
                log.error("Failed to initialize HttpSecurity for flow [{}]: {}",
                        flow.typeName(), ex.getMessage(), ex);
                // → swallow: continue;
                // → rethrow: throw new IllegalStateException("flow 초기화 실패: " + flow.typeName(), ex);
            }
        }

        return contexts;
    }

    private void initConfigurers() {
        for (SecurityConfigurer cfg : configurers) {
            cfg.init(context, config);
        }
    }

    private void configureFlows(List<FlowContext> flows) throws Exception {
        for (FlowContext fc : flows) {
            for (SecurityConfigurer cfg : configurers) {
                cfg.configure(fc);
            }
        }
    }

    private void registerSecurityFilterChains(List<FlowContext> flows) {
        flows.forEach(fc -> {
            try {
                DefaultSecurityFilterChain chain = fc.http().build();
                OrderedSecurityFilterChain osc = new OrderedSecurityFilterChain(
                        Ordered.HIGHEST_PRECEDENCE,
                        chain.getRequestMatcher(),
                        chain.getFilters()
                );
                String beanName = fc.flow().typeName() + "SecurityFilterChain" + chainOrder.getAndIncrement();
                context.registerChain(beanName, osc);
                context.registerAsBean(beanName, osc);
            } catch (Exception e) {
                throw new IllegalStateException("SecurityFilterChain 생성 실패 for flow: "
                        + fc.flow().typeName(), e);
            }
        });
    }
}

