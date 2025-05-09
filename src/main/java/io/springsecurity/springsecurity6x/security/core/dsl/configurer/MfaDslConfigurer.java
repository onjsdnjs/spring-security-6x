/*
package io.springsecurity.springsecurity6x.security.core.dsl;

import io.springsecurity.springsecurity6x.security.core.dsl.CommonSecurityDsl;
import io.springsecurity.springsecurity6x.security.core.dsl.impl.FormDslConfigurerImpl;
import io.springsecurity.springsecurity6x.security.core.dsl.impl.MfaDslConfigurerImpl;
import org.springframework.security.config.Customizer;

import java.util.function.Consumer;

*/
/**
 * MFA(다중 인증) 플로우 설정 DSL을 정의하는 인터페이스입니다.
 * <p>
 * 사용자는 이 DSL을 통해 여러 인증 단계를 순차적으로 구성할 수 있으며,
 * 플랫폼은 지정된 순서대로 각 인증 단계를 실행합니다.
 *//*

public interface MfaDslConfigurer extends CommonSecurityDsl<MfaDslConfigurerImpl> {

    */
/**
     * Form 인증 단계를 첫 번째 또는 다음 단계로 추가합니다.
     *
     * @param customizer FormDslConfigurer 설정 람다
     * @return this
     *//*

    MfaDslConfigurer form(Customizer<FormDslConfigurer> customizer);

    */
/**
     * REST 인증 단계를 추가합니다.
     *
     * @param customizer RestDslConfigurer 설정 람다
     * @return this
     *//*

    MfaDslConfigurer rest(Customizer<RestDslConfigurer> customizer);

    */
/**
     * OTT 인증 단계를 추가합니다.
     *
     * @param customizer OttDslConfigurer 설정 람다
     * @return this
     *//*

    MfaDslConfigurer ott(Customizer<OttDslConfigurer> customizer);

    */
/**
     * Passkey 인증 단계를 추가합니다.
     *
     * @param customizer PasskeyDslConfigurer 설정 람다
     * @return this
     *//*

    MfaDslConfigurer passkey(Customizer<PasskeyDslConfigurer> customizer);
}

*/
