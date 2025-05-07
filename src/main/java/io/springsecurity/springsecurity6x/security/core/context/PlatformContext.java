package io.springsecurity.springsecurity6x.security.core.context;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
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
public interface PlatformContext {

    /**
     * DSL로 수집된 AuthenticationStepConfig를 저장합니다.
     */
    void addAuthConfig(AuthenticationStepConfig config);

    /**
     * 저장된 AuthenticationStepConfig 리스트를 읽기 전용으로 반환합니다.
     */
    List<AuthenticationStepConfig> getAuthConfigs();

    /**
     * 공유 객체를 등록합니다.
     * 예: AuthenticationConfig, StateConfig, 기타 공용 객체
     */
    <T> void share(Class<T> clz, T obj);

    /**
     * 공유 객체를 가져옵니다.
     */
    <T> T getShared(Class<T> clz);
    /**
     * 스프링이 주입한 HttpSecurity 인스턴스를 반환합니다.
     */
    HttpSecurity http();

    /**
     * 새로운 HttpSecurity 인스턴스를 반환합니다.
     * 인증 방식/흐름별로 SecurityFilterChain을 분리하기 위해 사용합니다.
     */
    HttpSecurity newHttp() throws Exception;

    /**
     * 생성된 SecurityFilterChain을 등록합니다.
     * @param id    플로우 식별자
     * @param chain SecurityFilterChain
     */
    void registerChain(String id, SecurityFilterChain chain);

    void registerAsBean(String name, SecurityFilterChain  chain);

    /**
     * 등록된 모든 SecurityFilterChain을 읽기 전용으로 반환합니다.
     */
    Map<String, SecurityFilterChain> getChains();

    ApplicationContext applicationContext();
}

