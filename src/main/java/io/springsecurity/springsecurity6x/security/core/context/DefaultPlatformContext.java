package io.springsecurity.springsecurity6x.security.core.context;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 플랫폼 컨텍스트: DSL로 수집된 설정과
 * 스프링이 주입한 HttpSecurity 인스턴스를 보관하며,
 * AuthenticationFeature 및 SecurityFeature 구현체에게 공유합니다.
 */
@Component
public class DefaultPlatformContext implements PlatformContext{

    private HttpSecurity http;
    private final ApplicationContext applicationContext;
    private final ObjectProvider<HttpSecurity> httpProvider;
    private final List<AuthenticationStepConfig> authConfigs = new ArrayList<>();
    private final Map<Class<?>, Object> shared = new HashMap<>();
    private final Map<String, SecurityFilterChain> chains = new HashMap<>();
    private final Map<AuthenticationFlowConfig, HttpSecurity> flowHttpMap = new HashMap<>();

    public DefaultPlatformContext(ApplicationContext applicationContext, ObjectProvider<HttpSecurity> httpProvider) {
        this.applicationContext = applicationContext;
        this.httpProvider = httpProvider;
    }

    @Override
    public void addAuthConfig(AuthenticationStepConfig config) {
        this.authConfigs.add(config);
    }

    @Override
    public List<AuthenticationStepConfig> getAuthConfigs() {
        return List.copyOf(authConfigs);
    }

    @Override
    public <T> void share(Class<T> clz, T obj) {
        shared.put(clz, obj);
    }

    @Override
    public <T> T getShared(Class<T> clz) {
        return (T) shared.get(clz);
    }

    @Override
    public void registerHttp(AuthenticationFlowConfig flow, HttpSecurity http) {
        flowHttpMap.put(flow, http);
    }

    @Override
    public HttpSecurity http(AuthenticationFlowConfig flow) {
        return flowHttpMap.get(flow);
    }

    @Override
    public HttpSecurity newHttp() throws Exception {
        http = httpProvider.getObject();
        return http;
    }

    @Override
    public void registerChain(String id, SecurityFilterChain chain) {
        chains.put(id, chain);
    }

    @Override
    public void registerAsBean(String name, SecurityFilterChain  chain) {
        if (applicationContext instanceof ConfigurableApplicationContext configurable) {
            ConfigurableListableBeanFactory factory = configurable.getBeanFactory();
            if (!factory.containsBean(name)) {
                BeanDefinitionRegistry registry = (BeanDefinitionRegistry) factory;
                BeanDefinitionBuilder builder = BeanDefinitionBuilder
                        .genericBeanDefinition(SecurityFilterChain.class, () -> chain);
                registry.registerBeanDefinition(name, builder.getBeanDefinition());
            }
        }
    }

    @Override
    public Map<String, SecurityFilterChain> getChains() {
        return Map.copyOf(chains);
    }

    @Override
    public ApplicationContext applicationContext() {
        return applicationContext;
    }
}

