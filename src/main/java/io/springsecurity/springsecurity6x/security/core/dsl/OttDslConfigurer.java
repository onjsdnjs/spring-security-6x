package io.springsecurity.springsecurity6x.security.core.dsl;

/**
 * OTT(One-Time Token) 로그인 관련 DSL 설정을 정의하는 인터페이스입니다.
 * <p>
 * 사용자는 이 DSL을 통해 OTT 로그인 처리 엔드포인트와 매처를 설정하고,
 * 이를 기반으로 플랫폼이 HttpSecurity에 OTT 인증 필터를 적용합니다.
 */
public interface OttDslConfigurer {

    OttDslConfigurer matchers(String... patterns);

    OttDslConfigurer loginProcessingUrl(String url);
}

