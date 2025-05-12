package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.OrderedSecurityFilterChain;
import jakarta.servlet.Filter;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class SecurityFilterChainRegistrar {

    private final FeatureRegistry featureRegistry;
    private final Map<String, Class<? extends Filter>> stepToFilter;

    public SecurityFilterChainRegistrar(FeatureRegistry featureRegistry,
                                        Map<String, Class<? extends Filter>> stepToFilter) {
        this.featureRegistry = featureRegistry;
        this.stepToFilter    = stepToFilter;
    }

    /**
     * FlowContext 리스트를 받아, 동적으로 SecurityFilterChain 빈을 등록합니다.
     */
    public void registerSecurityFilterChains(List<FlowContext> flows, ApplicationContext context) {

        ConfigurableApplicationContext cac = (ConfigurableApplicationContext) context;
        BeanDefinitionRegistry registry = (BeanDefinitionRegistry) cac.getBeanFactory();

        AtomicInteger idx = new AtomicInteger(0);

        for (FlowContext fc : flows) {
            String flowName = fc.flow().typeName();
            int orderVal    = fc.flow().order();
            String beanName = flowName + "SecurityFilterChain" + idx.incrementAndGet();

            BeanDefinitionBuilder builder = BeanDefinitionBuilder
                    .genericBeanDefinition(SecurityFilterChain.class, () -> {
                        try {
                            DefaultSecurityFilterChain built = fc.http().build();

                            for (AuthenticationStepConfig step : fc.flow().stepConfigs()) {
                                Class<? extends Filter> filterClass = stepToFilter.get(step.type());
                                if (filterClass == null) {
                                    throw new IllegalStateException("알 수 없는 MFA 단계: " + step.type());
                                }
                                Filter f = built.getFilters().stream()
                                        .filter(filterClass::isInstance)
                                        .findFirst()
                                        .orElseThrow(() ->
                                                new IllegalStateException(
                                                        "필터를 찾을 수 없습니다 for type: " + step.type()));
                                featureRegistry.registerFactorFilter(step.type(), f);
                            }

                            return new OrderedSecurityFilterChain(
                                    Ordered.HIGHEST_PRECEDENCE + orderVal,
                                    built.getRequestMatcher(),
                                    built.getFilters()
                            );
                        } catch (Exception ex) {
                            throw new BeanCreationException(
                                    "SecurityFilterChain 생성 실패 for flow: " + fc.flow().typeName(), ex);
                        }
                    });
            builder.setLazyInit(true);
            builder.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
            registry.registerBeanDefinition(beanName, builder.getBeanDefinition());
        }
    }

    public void registerSecurityFilterChains2(
            List<FlowContext> flows,
            ApplicationContext context) {

        ConfigurableApplicationContext cac = (ConfigurableApplicationContext) context;
        BeanDefinitionRegistry registry = (BeanDefinitionRegistry) cac.getBeanFactory();
        AtomicInteger idx = new AtomicInteger(0);

        // MFA 경로 전용 매처
        RequestMatcher mfaMatcher = new AntPathRequestMatcher("/api/auth/mfa/**");

        for (FlowContext fc : flows) {
            String name     = fc.flow().typeName();
            int    orderVal = fc.flow().order();
            String beanName = name + "SecurityFilterChain" + idx.incrementAndGet();

            // FlowContext가 MFA flow 인지 판별 (예: 이름 또는 타입으로)
            boolean isMfaFlow = name.equalsIgnoreCase("mfa");

            // 단일 vs MFA 복합 매처 구성
            RequestMatcher matcher = isMfaFlow ? mfaMatcher : new AndRequestMatcher(new AntPathRequestMatcher("/api/**"),
                                                                                    new NegatedRequestMatcher(mfaMatcher)
            );

            BeanDefinitionBuilder builder = BeanDefinitionBuilder
                    .genericBeanDefinition(SecurityFilterChain.class, () -> {
                        try {
                            DefaultSecurityFilterChain built = fc.http()
                                    .securityMatcher(matcher)   // 핵심: 복합 matcher 적용
                                    .build();

                            // MFA 필터 인스턴스 등록 (기존 로직 그대로)
                            for (AuthenticationStepConfig step : fc.flow().stepConfigs()) {
                                Class<? extends Filter> cls = stepToFilter.get(step.type());
                                if (cls == null) {
                                    throw new IllegalStateException("알 수 없는 MFA 단계: " + step.type());
                                }
                                Filter f = built.getFilters().stream()
                                        .filter(cls::isInstance)
                                        .findFirst()
                                        .orElseThrow(() -> new IllegalStateException(
                                                "필터를 찾을 수 없습니다 for type: " + step.type()));
                                featureRegistry.registerFactorFilter(step.type(), f);
                            }

                            return new OrderedSecurityFilterChain(
                                    Ordered.HIGHEST_PRECEDENCE + orderVal,
                                    built.getRequestMatcher(),
                                    built.getFilters()
                            );
                        } catch (Exception ex) {
                            throw new BeanCreationException(
                                    "SecurityFilterChain 생성 실패 for flow: " + name, ex);
                        }
                    });

            builder.setLazyInit(true);
            builder.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
            registry.registerBeanDefinition(beanName, builder.getBeanDefinition());
        }
    }
}

