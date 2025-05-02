package io.springsecurity.springsecurity6x.security.init;

import io.springsecurity.springsecurity6x.security.builder.PlatformSecurityChainBuilder;
import io.springsecurity.springsecurity6x.security.dsl.state.jwt.JwtStateConfigurerImpl;
import io.springsecurity.springsecurity6x.security.dsl.state.session.SessionStateConfigurerImpl;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

/**
 * DSL 기반으로 등록된 인증 설정을 기반으로 SecurityFilterChain을 동적으로 Bean으로 등록한다.
 */
public class DynamicSecurityRegistrar implements BeanDefinitionRegistryPostProcessor {

    private final IdentityDslRegistry registry;
    private final ObjectProvider<HttpSecurity> httpSecurityProvider;
    private final JwtStateConfigurerImpl jwtConfigurer;
    private final SessionStateConfigurerImpl sessionConfigurer;

    public DynamicSecurityRegistrar(
            IdentityDslRegistry registry,
            ObjectProvider<HttpSecurity> httpSecurityProvider,
            JwtStateConfigurerImpl jwtConfigurer,
            SessionStateConfigurerImpl sessionConfigurer) {
        this.registry = registry;
        this.httpSecurityProvider = httpSecurityProvider;
        this.jwtConfigurer = jwtConfigurer;
        this.sessionConfigurer = sessionConfigurer;
    }

    @Override
    public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
        PlatformSecurityChainBuilder builder = new PlatformSecurityChainBuilder(
                httpSecurityProvider, jwtConfigurer, sessionConfigurer);

        try {
            List<SecurityFilterChain> chains = builder.buildChains(this.registry.config());
            int count = 1;
            for (SecurityFilterChain chain : chains) {
                String beanName = "securityFilterChain_" + count++;
                BeanDefinitionBuilder bldr = BeanDefinitionBuilder
                        .genericBeanDefinition(SecurityFilterChain.class, () -> chain)
                        .setLazyInit(false);

                registry.registerBeanDefinition(beanName, bldr.getBeanDefinition());
            }
        } catch (Exception e) {
            throw new RuntimeException("SecurityFilterChain 동적 생성 실패", e);
        }
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        // 필요 없음
    }
}

