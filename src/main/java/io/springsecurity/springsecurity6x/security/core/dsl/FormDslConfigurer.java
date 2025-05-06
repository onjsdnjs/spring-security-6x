package io.springsecurity.springsecurity6x.security.core.dsl;

/**
 * Form 로그인 관련 DSL 설정을 정의하는 인터페이스입니다.
 * <p>
 * 사용자는 이 DSL을 통해 Form 로그인 엔드포인트, 요청 매처, 파라미터 이름 등을
 * 설정할 수 있으며, 이를 기반으로 플랫폼이 HttpSecurity에 FormLoginConfigurer를 적용합니다.
 */

import io.springsecurity.springsecurity6x.security.core.dsl.common.CommonSecurityDsl;
import io.springsecurity.springsecurity6x.security.core.dsl.impl.FormDslConfigurerImpl;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * Form 기반 인증 DSL 인터페이스
 */
public interface FormDslConfigurer extends CommonSecurityDsl<FormDslConfigurerImpl> {

    FormDslConfigurer matchers(String... patterns);
    FormDslConfigurer loginPage(String loginPageUrl);
    FormDslConfigurer loginProcessingUrl(String loginProcessingUrl);
    FormDslConfigurer usernameParameter(String usernameParameter);
    FormDslConfigurer passwordParameter(String passwordParameter);
    FormDslConfigurer defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse);
    FormDslConfigurer failureUrl(String failureUrl);
    FormDslConfigurer successHandler(AuthenticationSuccessHandler successHandler);
    FormDslConfigurer failureHandler(AuthenticationFailureHandler failureHandler);
    FormDslConfigurer securityContextRepository(SecurityContextRepository repository);

    /**
     * Advanced: raw FormLoginConfigurer access for full API coverage
     */
    FormDslConfigurer raw(Customizer<FormLoginConfigurer<HttpSecurity>> customizer);
}
