package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.OrderedSecurityFilterChain;
import io.springsecurity.springsecurity6x.security.core.mfa.context.FactorIdentifier;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import jakarta.servlet.Filter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SecurityFilterChainRegistrar 리팩토링 버전
 * - stepToFilter를 Class가 아닌 실제 Filter 인스턴스 맵으로 주입
 * - buildChain 책임 분리
 * - BeanDefinition 생성 로직 분리로 가독성 향상
 */
@Slf4j
public class SecurityFilterChainRegistrar {
    private final ConfiguredFactorFilterProvider configuredFactorFilterProvider;
    private final Map<String, Class<? extends Filter>> stepFilterClasses;
    private final AdapterRegistry adapterRegistry;

    // 기본 팩터 타입들 정의
    private static final Set<String> DEFAULT_FACTOR_TYPES = Set.of(
            AuthType.OTT.name().toLowerCase(),
            AuthType.PASSKEY.name().toLowerCase()
    );

    public SecurityFilterChainRegistrar(ConfiguredFactorFilterProvider configuredFactorFilterProvider,
                                        Map<String, Class<? extends Filter>> stepFilterClasses, AdapterRegistry adapterRegistry) {
        this.configuredFactorFilterProvider = Objects.requireNonNull(configuredFactorFilterProvider, "ConfiguredFactorFilterProvider cannot be null.");
        this.stepFilterClasses  = Objects.requireNonNull(stepFilterClasses, "stepFilterClasses cannot be null.");
        this.adapterRegistry = adapterRegistry;
    }

    public void registerSecurityFilterChains(List<FlowContext> flows, ApplicationContext context) {
        Assert.notNull(flows, "Flows list cannot be null.");
        Assert.notNull(context, "ApplicationContext cannot be null.");

        if (!(context instanceof ConfigurableApplicationContext cac)) {
            log.warn("ApplicationContext is not a ConfigurableApplicationContext. Cannot register SecurityFilterChain beans dynamically.");
            return;
        }
        BeanDefinitionRegistry registry = (BeanDefinitionRegistry) cac.getBeanFactory();
        AtomicInteger idx = new AtomicInteger(0);

        // 1. 명시적으로 설정된 팩터들 먼저 등록
        Set<String> configuredFactorTypes = new HashSet<>();

        for (FlowContext fc : flows) {
            Objects.requireNonNull(fc, "FlowContext in list cannot be null.");
            AuthenticationFlowConfig flowConfig = Objects.requireNonNull(fc.flow(), "AuthenticationFlowConfig in FlowContext cannot be null.");
            String flowTypeName = Objects.requireNonNull(flowConfig.getTypeName(), "Flow typeName cannot be null.");

            // 설정된 팩터 타입 수집
            if (AuthType.MFA.name().equalsIgnoreCase(flowTypeName)) {
                flowConfig.getStepConfigs().stream()
                        .map(step -> step.getType().toLowerCase())
                        .filter(type -> !type.equals("primary"))
                        .forEach(configuredFactorTypes::add);
            }

            String beanName = flowTypeName + "SecurityFilterChain" + idx.incrementAndGet();
            BeanDefinition bd = BeanDefinitionBuilder
                    .genericBeanDefinition(SecurityFilterChain.class, () -> buildAndRegisterFilters(fc)) // 메소드명 변경 및 fc 전달
                    .setLazyInit(false)
                    .setRole(BeanDefinition.ROLE_INFRASTRUCTURE)
                    .getBeanDefinition();
            registry.registerBeanDefinition(beanName, bd);
            log.info("Registered SecurityFilterChain bean: {} for flow type: {}", beanName, flowTypeName);
        }
        // 2. 설정되지 않은 기본 팩터들에 대한 SecurityFilterChain 생성
        DefaultFactorChainProvider defaultProvider = new DefaultFactorChainProvider(context, this, adapterRegistry); // this 전달
        defaultProvider.registerDefaultFactorChains(configuredFactorTypes, registry, idx);

    }

    // 메소드명 변경 및 fc를 인자로 받음
    public OrderedSecurityFilterChain buildAndRegisterFilters(FlowContext fc) {
        try {
            AuthenticationFlowConfig flowConfig = fc.flow();
            log.debug("Building SecurityFilterChain and registering factor filters for flow: type='{}', order={}",
                    flowConfig.getTypeName(), flowConfig.getOrder());

            DefaultSecurityFilterChain builtChain = fc.http().build();
            log.debug("Successfully built DefaultSecurityFilterChain for flow: {}", flowConfig.getTypeName());

            for (AuthenticationStepConfig step : flowConfig.getStepConfigs()) {
                Objects.requireNonNull(step, "AuthenticationStepConfig in flow cannot be null.");
                String pureFactorType = Objects.requireNonNull(step.getType(), "Step type cannot be null.").toLowerCase();
                String stepId = step.getStepId();

                if (!StringUtils.hasText(stepId)) {
                    log.error("CRITICAL: AuthenticationStepConfig (type: {}, order: {}) in flow '{}' is missing a stepId. " +
                                    "This step's filter cannot be registered in ConfiguredFactorFilterProvider.",
                            pureFactorType, step.getOrder(), flowConfig.getTypeName());
                    continue;
                }

                // 1차 인증 스텝은 MfaStepFilterWrapper의 위임 대상이 아니므로 등록 불필요
                if ("mfa".equalsIgnoreCase(flowConfig.getTypeName()) && step.getOrder() == 0) {
                    log.trace("Skipping filter registration for primary auth step '{}' (id: {}) in MFA flow '{}'",
                            pureFactorType, stepId, flowConfig.getTypeName());
                    continue;
                }

                Class<? extends Filter> filterClass = stepFilterClasses.get(pureFactorType);
                if (filterClass == null) {
                    log.error("No filter class configured in stepFilterClasses for step type: '{}' (id: {}) in flow: '{}'",
                            pureFactorType, stepId, flowConfig.getTypeName());
                    throw new IllegalStateException("필터 클래스 미설정: " + pureFactorType + " (flow: " + flowConfig.getTypeName() + ")");
                }

                Optional<Filter> foundFilterOptional = builtChain.getFilters().stream()
                        .filter(filterClass::isInstance)
                        .findFirst();

                if (foundFilterOptional.isEmpty()) {
                    log.error("Filter of type {} not found in the built SecurityFilterChain for step: '{}' in flow: '{}'. Critical configuration error.",
                            filterClass.getName(), stepId, flowConfig.getTypeName());
                    throw new IllegalStateException("빌드된 체인에서 필터 인스턴스를 찾을 수 없습니다: " + stepId + " (flow: " + flowConfig.getTypeName() + ")");
                }

                Filter actualFilterInstance = foundFilterOptional.get();
                // FactorIdentifier 생성: flowConfig의 typeName과 step의 stepId 사용
                FactorIdentifier registrationKey = FactorIdentifier.of(flowConfig.getTypeName(), stepId);

                configuredFactorFilterProvider.registerFilter(registrationKey, actualFilterInstance);
            }

            return new OrderedSecurityFilterChain(
                    Ordered.HIGHEST_PRECEDENCE + flowConfig.getOrder(),
                    builtChain.getRequestMatcher(),
                    builtChain.getFilters()
            );
        } catch (Exception e) {
            log.error("Error building SecurityFilterChain or registering factor filters for flow: {}", fc.flow().getTypeName(), e);
            throw new RuntimeException("Failed to build SecurityFilterChain for flow " + fc.flow().getTypeName(), e);
        }
    }
}




