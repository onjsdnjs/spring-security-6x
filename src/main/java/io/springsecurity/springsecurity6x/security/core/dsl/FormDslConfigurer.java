package io.springsecurity.springsecurity6x.security.core.dsl;

/**
 * Form 로그인 관련 DSL 설정을 정의하는 인터페이스입니다.
 * <p>
 * 사용자는 이 DSL을 통해 Form 로그인 엔드포인트, 요청 매처, 파라미터 이름 등을
 * 설정할 수 있으며, 이를 기반으로 플랫폼이 HttpSecurity에 FormLoginConfigurer를 적용합니다.
 */

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;

/**
 * Form 로그인 DSL: 실제 HttpSecurity.formLogin() 은 하지 않고,
 * Customizer<FormLoginConfigurer<HttpSecurity>> 만 저장합니다.
 */
public interface FormDslConfigurer {
    /**
     * FormLoginConfigurer<HttpSecurity>에 적용할 설정을 람다로 받습니다.
     * @param customizer f.loginPage(...), f.failureUrl(...) 등
     * @return this
     */
    FormDslConfigurer login(Customizer<FormLoginConfigurer<HttpSecurity>> customizer);
}
