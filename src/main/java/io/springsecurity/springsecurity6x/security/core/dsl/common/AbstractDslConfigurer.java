package io.springsecurity.springsecurity6x.security.core.dsl.common;

import io.springsecurity.springsecurity6x.security.core.config.AuthenticationStepConfig;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.util.function.ThrowingConsumer;

import java.util.Objects;

/**
 * 추상 DSL Configurer의 기본 동작을 제공하는 베이스 클래스
 *
 * @param <O> 옵션 객체 타입
 * @param <D> DSL 구현 타입
 */
public abstract class AbstractDslConfigurer<O, D extends CommonSecurityDsl<D>> implements CommonSecurityDsl<D> {

    protected final AuthenticationStepConfig stepConfig;
    protected final O options;

    protected AbstractDslConfigurer(AuthenticationStepConfig stepConfig, O options) {
        this.stepConfig = Objects.requireNonNull(stepConfig, "stepConfig must not be null");
        this.options = Objects.requireNonNull(options, "options must not be null");
    }

    /**
     * 생성된 stepConfig를 반환
     */
    public AuthenticationStepConfig getStepConfig() {
        return stepConfig;
    }

    // 공통 DSL 메서드 stub 구현
    @Override
    public D disableCsrf() { return (D) this; }

    @Override
    public D cors(Customizer<CorsConfigurer<HttpSecurity>> customizer) { return (D) this; }

    @Override
    public D headers(Customizer<HeadersConfigurer<HttpSecurity>> customizer) { return (D) this; }

    @Override
    public D sessionManagement(Customizer<SessionManagementConfigurer<HttpSecurity>> customizer) { return (D) this; }

    @Override
    public D authorizeStatic(String... patterns) { return (D) this; }
}