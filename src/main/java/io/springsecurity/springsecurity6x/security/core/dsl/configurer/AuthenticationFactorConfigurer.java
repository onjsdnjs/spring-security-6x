package io.springsecurity.springsecurity6x.security.core.dsl.configurer;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.BaseAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.dsl.common.OptionsBuilderDsl;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SecurityConfigurerDsl;
import io.springsecurity.springsecurity6x.security.core.dsl.option.AuthenticationProcessingOptions;
import org.springframework.security.config.Customizer;

/**
 * 모든 인증 방식(Factor) 설정자(Configurer)의 기본 인터페이스.
 * @param <O> 빌드될 Option의 타입
 * @param <A> 해당 DSL 스코프의 ASEP Attributes 타입
 * @param <S> Configurer 자신의 타입 (해당 인터페이스를 구현하는 구체적인 Configurer 인터페이스)
 */
public interface AuthenticationFactorConfigurer<
        O extends AuthenticationProcessingOptions, // O의 bound는 AuthenticationProcessingOptions
        A extends BaseAsepAttributes,
        S extends AuthenticationFactorConfigurer<O, A, S>>
        extends OptionsBuilderDsl<O, S>, SecurityConfigurerDsl {

    S order(int order);
    S asep(Customizer<A> asepAttributesCustomizer);
}
