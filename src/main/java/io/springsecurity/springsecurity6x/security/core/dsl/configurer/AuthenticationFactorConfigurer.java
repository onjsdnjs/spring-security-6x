package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;

/**
 * 모든 인증 방식(Factor) 설정자(Configurer)의 기본 인터페이스.
 * 각 인증 방식에 특화된 Options 객체를 빌드하는 역할을 정의합니다.
 * @param <O> 빌드될 Option의 타입 (AuthenticationProcessingOptions 또는 그 하위 타입)
 * @param <S> Configurer 자신의 타입 (Self-referential generic type for fluent API)
 */
public interface AuthenticationFactorConfigurer<O extends AuthenticationProcessingOptions, S extends AuthenticationFactorConfigurer<O, S>>
        extends OptionsBuilderDsl<O, S> {

    S order(int order);
}
