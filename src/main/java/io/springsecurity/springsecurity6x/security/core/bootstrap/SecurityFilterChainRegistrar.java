package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.OrderedSecurityFilterChain;
import jakarta.servlet.Filter;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SecurityFilterChainRegistrar 리팩토링 버전
 * - stepToFilter를 Class가 아닌 실제 Filter 인스턴스 맵으로 주입
 * - buildChain 책임 분리
 * - BeanDefinition 생성 로직 분리로 가독성 향상
 */
public class SecurityFilterChainRegistrar {
    private final FeatureRegistry featureRegistry;
    private final Map<String, Class<? extends Filter>> stepFilterClasses;

    public SecurityFilterChainRegistrar(FeatureRegistry registry,
                                        Map<String, Class<? extends Filter>> stepFilterClasses) {
        this.featureRegistry    = registry;
        this.stepFilterClasses  = stepFilterClasses;
    }

    public void registerSecurityFilterChains(List<FlowContext> flows, ApplicationContext context) {

        ConfigurableApplicationContext cac = (ConfigurableApplicationContext) context;
        BeanDefinitionRegistry registry = (BeanDefinitionRegistry) cac.getBeanFactory();
        AtomicInteger idx = new AtomicInteger(0);

        for (FlowContext fc : flows) {
            String beanName = fc.flow().getTypeName() + "SecurityFilterChain" + idx.incrementAndGet();
            BeanDefinition bd = createBeanDefinition(fc);
            registry.registerBeanDefinition(beanName, bd);
        }
    }

    private BeanDefinition createBeanDefinition(FlowContext fc) {

        return BeanDefinitionBuilder
                .genericBeanDefinition(SecurityFilterChain.class, () -> buildChain(fc))
                .setLazyInit(true)
                .setRole(BeanDefinition.ROLE_INFRASTRUCTURE)
                .getBeanDefinition();
    }

    private OrderedSecurityFilterChain buildChain(FlowContext fc) {

        try {
            DefaultSecurityFilterChain  built = fc.http().build();
            for (AuthenticationStepConfig step : fc.flow().getStepConfigs()) {
                Class<? extends Filter> filterClass = stepFilterClasses.get(step.getType());
                if (filterClass == null) {
                    throw new IllegalStateException("알 수 없는 MFA 단계: " + step.getType());
                }
                Filter f = built.getFilters().stream()
                        .filter(filterClass::isInstance)
                        .findFirst()
                        .orElseThrow(() ->
                                new IllegalStateException("필터를 찾을 수 없습니다 for type: " + step.getType()));
                featureRegistry.registerFactorFilter(step.getType(), f);
            }

            return new OrderedSecurityFilterChain(
                    Ordered.HIGHEST_PRECEDENCE + fc.flow().getOrder(),
                    built.getRequestMatcher(),
                    built.getFilters()
            );
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}




