package io.springsecurity.springsecurity6x.security.core.dsl;

/**
 * Form 로그인 관련 DSL 설정을 정의하는 인터페이스입니다.
 * <p>
 * 사용자는 이 DSL을 통해 Form 로그인 엔드포인트, 요청 매처, 파라미터 이름 등을
 * 설정할 수 있으며, 이를 기반으로 플랫폼이 HttpSecurity에 FormLoginConfigurer를 적용합니다.
 */
public interface FormDslConfigurer {

    FormDslConfigurer matchers(String... patterns);

    FormDslConfigurer loginPage(String url);

    FormDslConfigurer loginProcessingUrl(String url);
}
