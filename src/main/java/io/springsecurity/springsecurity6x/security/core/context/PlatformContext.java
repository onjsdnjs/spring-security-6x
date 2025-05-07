package io.springsecurity.springsecurity6x.security.core.context;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.Ordered;
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
public class PlatformContext {

    private final HttpSecurity http;
    private final ApplicationContext applicationContext;
    private final List<AuthenticationStepConfig> authConfigs = new ArrayList<>();
    private final Map<Class<?>, Object> shared = new HashMap<>();
    private final Map<String, SecurityFilterChain> chains = new HashMap<>();

    /**
     * @param http 스프링이 주입한 HttpSecurity 빌더
     */
    public PlatformContext(HttpSecurity http, ApplicationContext applicationContext) {
        this.http = http;
        this.applicationContext = applicationContext;
    }

    /**
     * DSL로 수집된 AuthenticationStepConfig를 저장합니다.
     */
    public void addAuthConfig(AuthenticationStepConfig config) {
        this.authConfigs.add(config);
    }

    /**
     * 저장된 AuthenticationStepConfig 리스트를 읽기 전용으로 반환합니다.
     */
    public List<AuthenticationStepConfig> getAuthConfigs() {
        return List.copyOf(authConfigs);
    }

    /**
     * 공유 객체를 등록합니다.
     * 예: AuthenticationConfig, StateConfig, 기타 공용 객체
     */
    public <T> void share(Class<T> clz, T obj) {
        shared.put(clz, obj);
    }

    /**
     * 공유 객체를 가져옵니다.
     */
    public <T> T getShared(Class<T> clz) {
        return (T) shared.get(clz);
    }

    /**
     * 스프링이 주입한 HttpSecurity 인스턴스를 반환합니다.
     */
    public HttpSecurity http() {
        return http;
    }

    /**
     * 생성된 SecurityFilterChain을 등록합니다.
     * @param id    플로우 식별자
     * @param chain SecurityFilterChain
     */
    public void registerChain(String id, SecurityFilterChain chain) {
        chains.put(id, chain);
    }

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

    /**
     * 등록된 모든 SecurityFilterChain을 읽기 전용으로 반환합니다.
     */
    public Map<String, SecurityFilterChain> getChains() {
        return Map.copyOf(chains);
    }

    public ApplicationContext applicationContext() {
        return applicationContext;
    }
}

