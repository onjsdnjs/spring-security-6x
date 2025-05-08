package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.*;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.OrderedSecurityFilterChain;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SecurityPlatform 구현체
 * DSL 설정과 Feature 기반 설정을 조합하여 SecurityFilterChain을 생성 및 등록
 */
@Slf4j
public class SecurityPlatformInitializer implements SecurityPlatform {
    private final PlatformContext context;
    private final List<SecurityConfigurer> configurers;  // 플랫폼 기본 Configurer
    private final FeatureRegistry featureRegistry;       // 인증/상태 Feature 레지스트리
    private PlatformConfig config;
    private final AtomicInteger chainOrder = new AtomicInteger(1); // FilterChain 등록 순서 카운터

    /**
     * 생성자
     * @param context 플랫폼 컨텍스트
     * @param configurers 플랫폼 기본 Configurer 리스트
     * @param registry FeatureRegistry
     */
    public SecurityPlatformInitializer(PlatformContext context, List<SecurityConfigurer> configurers, FeatureRegistry registry) {
        this.context = context;
        this.configurers = configurers;
        this.featureRegistry = registry;
    }

    /**
     * 글로벌 설정 준비
     */
    @Override
    public void prepareGlobal(PlatformConfig config, List<?> features) {
        this.config = config;
    }

    /**
     * 플랫폼 초기화 실행
     */
    @Override
    public void initialize() {

        // 1) FlowContext 생성·정렬
        List<FlowContext> flows = createAndSortFlowContexts();

        // 2) 모든 Configurer 조합
        List<SecurityConfigurer> configurers = buildConfigurers();

        // 3) init 단계 실행
        initConfigurers(configurers);

        // 4) configure 단계 실행
        configureFlows(configurers, flows);

        // 5) SecurityFilterChain 등록
        registerSecurityFilterChains(flows);
    }

    /**
     * FlowContext 생성 후 DSL .order() 기준으로 정렬
     */
    private List<FlowContext> createAndSortFlowContexts() {
        List<FlowContext> flows = createFlowContexts();
        flows.sort(Comparator.comparingInt(fc -> fc.flow().order()));
        return flows;
    }

    /**
     * 각 AuthenticationFlowConfig에 대응하는 FlowContext 리스트 생성
     */
    private List<FlowContext> createFlowContexts() {
        List<FlowContext> contexts = new ArrayList<>();
        for (AuthenticationFlowConfig flow : config.flows()) {
            try {
                HttpSecurity http = context.newHttp();
                context.registerHttp(flow, http);
                FlowContext fc = new FlowContext(flow, http, context, config);
                context.share(FlowContext.class, fc);
                contexts.add(fc);
            } catch (Exception ex) {
                log.error("FlowContext 생성 실패 - flow=[{}]", flow.typeName(), ex);
            }
        }
        return contexts;
    }

    /**
     * 플랫폼 기본 + Feature 어댑터 + 사용자 DSL Configurer 조합
     */
    private List<SecurityConfigurer> buildConfigurers() {

        List<SecurityConfigurer> list = new ArrayList<>(configurers);

        featureRegistry.getAuthFeaturesFor(config.flows())
                .forEach(f -> list.add(new AuthFeatureConfigurerAdapter(f)));

        featureRegistry.getStateFeaturesFor(config.flows())
                .forEach(sf -> list.add(new StateFeatureConfigurerAdapter(sf, context)));

        return list;
    }

    /**
     * init(context, config) 단계 실행
     */
    private void initConfigurers(List<SecurityConfigurer> configurers){
        configurers.stream()
                .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                .forEach(cfg -> {
                    try {
                        cfg.init(context, config);
                    } catch (Exception e) {
                        throw new IllegalStateException("Configurer init 실패: " + cfg, e);
                    }
                });
    }

    /**
     * configure(fc) 단계 실행
     */
    private void configureFlows(List<SecurityConfigurer> configurers, List<FlowContext> flows){
        configurers.stream()
                .sorted(Comparator.comparingInt(SecurityConfigurer::getOrder))
                .forEach(cfg -> flows.forEach(fc -> {
                    try {
                        cfg.configure(fc);
                    } catch (Exception e) {
                        throw new IllegalStateException("Configurer configure 실패: " + cfg, e);
                    }
                }));
    }

    /**
     * FlowContext 별로 SecurityFilterChain 생성 및 Bean 등록
     */
    private void registerSecurityFilterChains(List<FlowContext> flows) {
        ConfigurableApplicationContext cac = (ConfigurableApplicationContext) context.applicationContext();
        BeanDefinitionRegistry registry = (BeanDefinitionRegistry) cac.getBeanFactory();
        for (FlowContext fc : flows) {
            String flowName = fc.flow().typeName();
            int orderVal = fc.flow().order();
            String beanName = flowName + "SecurityFilterChain" + chainOrder.getAndIncrement();
            BeanDefinitionBuilder builder = BeanDefinitionBuilder.genericBeanDefinition(
                    SecurityFilterChain.class,
                    () -> {
                        try {
                            DefaultSecurityFilterChain built = fc.http().build();
                            return new OrderedSecurityFilterChain(
                                    Ordered.HIGHEST_PRECEDENCE + orderVal,
                                    built.getRequestMatcher(),
                                    built.getFilters());
                        } catch (Exception ex) {
                            throw new BeanCreationException(
                                    "SecurityFilterChain 생성 실패 for flow: " + flowName, ex);
                        }
                    }
            );
            builder.setLazyInit(true);
            builder.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
            registry.registerBeanDefinition(beanName, builder.getBeanDefinition());
        }
    }
}

