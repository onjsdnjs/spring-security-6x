package io.springsecurity.springsecurity6x.security.core.spi;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.feature.AuthenticationFeature;
import io.springsecurity.springsecurity6x.security.core.feature.StateFeature;
import io.springsecurity.springsecurity6x.security.core.feature.impl.CompositeSecurityFeature;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

/**
 * BeanDefinitionRegistryPostProcessor 구현체로, PlatformConfig에 정의된
 * 모든 인증·상태 플로우(AuthenticationFlowConfig)를 읽어들여
 * CompositeSecurityFeature 빈을 동적으로 등록합니다.
 * <p>
 * - Flow 마다 AuthenticationFeature, StateFeature 빈을 조회하고,
 *   CompositeSecurityFeature 생성자에 주입하여 체인 ID("chain_" + flowId)로 빈을 등록합니다.
 * - Ordered.HIGHEST_PRECEDENCE를 사용해 스프링 시큐리티의 기본 체인 등록 전에 실행됩니다.
 */
@Component
public class FeatureRegistrar implements BeanDefinitionRegistryPostProcessor, Ordered, org.springframework.beans.factory.BeanFactoryAware {
    private org.springframework.beans.factory.BeanFactory factory;

    public FeatureRegistrar() {
    }

    @Override
    public void setBeanFactory(org.springframework.beans.factory.BeanFactory beanFactory) throws org.springframework.beans.BeansException {
        this.factory = beanFactory;
    }

    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) {
        PlatformConfig cfg = factory.getBean(PlatformConfig.class);
        Customizer<HttpSecurity> global = cfg.getGlobal();
        for (AuthenticationFlowConfig flow : cfg.getFlows()) {
            // 순서에 맞게 인자 배치: id, globalCustomizer, stateFeature, steps
            List<AuthenticationFeature> steps = flow.getSteps().stream()
                    .map(stepCfg -> factory.getBean(AuthenticationFeature.class, stepCfg.getType()))
                    .collect(Collectors.toList());
            StateFeature state = factory.getBean(StateFeature.class, flow.getState().getState());
            String beanName = "chain_" + flow.getType();
            BeanDefinitionBuilder bd = BeanDefinitionBuilder
                    .genericBeanDefinition(CompositeSecurityFeature.class)
                    .addConstructorArgValue(flow.getType())
                    .addConstructorArgValue(global)
                    .addConstructorArgValue(state)
                    .addConstructorArgValue(steps);
            registry.registerBeanDefinition(beanName, bd.getBeanDefinition());
        }
    }

    @Override
    public void postProcessBeanFactory(org.springframework.beans.factory.config.ConfigurableListableBeanFactory beanFactory) {
        // do nothing
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}

