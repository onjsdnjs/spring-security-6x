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
 * Form 로그인 DSL: 스프링 FormLoginConfigurer API를
 * 있는 그대로 Consumer<…> 형태로 캡처합니다.
 */
public interface FormDslConfigurer {
    /**
     * FormLoginConfigurer<HttpSecurity>의 모든 메서드를
     * 프록시를 통해 그대로 호출·캡처합니다.
     */
    FormDslConfigurer formLogin(Customizer<FormLoginConfigurer<HttpSecurity>> customizer);
}
