package io.springsecurity.springsecurity6x.security.core.dsl.option;

import lombok.Getter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;

import java.util.Objects;

/**
 * 인증 처리와 관련된 공통 옵션들을 정의하는 추상 클래스입니다.
 * 각 구체적인 인증 방식(Form, REST 등)의 Options 클래스는 이 클래스를 상속합니다.
 */
@Getter
public abstract class AuthenticationProcessingOptions extends AbstractOptions {
    private final String loginProcessingUrl;
    private final int order; // Configurer 또는 Filter의 적용 순서
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;
    private final SecurityContextRepository securityContextRepository;

    protected AuthenticationProcessingOptions(AbstractAuthenticationProcessingOptionsBuilder<?, ?> builder) {
        super(builder); // 부모 생성자 호출
        Objects.requireNonNull(builder, "Builder cannot be null");
        this.loginProcessingUrl = builder.loginProcessingUrl; // null 가능 (예: AbstractHttpConfigurer만 사용하는 경우)
        this.order = builder.order;
        this.successHandler = builder.successHandler; // null 가능 (기본 핸들러 사용)
        this.failureHandler = builder.failureHandler; // null 가능 (기본 핸들러 사용)
        this.securityContextRepository = builder.securityContextRepository; // null 가능 (기본 저장소 사용)
    }

    /**
     * AuthenticationProcessingOptions를 빌드하기 위한 추상 빌더 클래스입니다.
     * @param <O> 빌드될 Options의 구체적인 타입
     * @param <B> 빌더 자신의 구체적인 타입 (Self-referential)
     */
    public abstract static class AbstractAuthenticationProcessingOptionsBuilder
            <O extends AuthenticationProcessingOptions, B extends AbstractAuthenticationProcessingOptionsBuilder<O, B>>
            extends AbstractOptions.Builder<O, B> {

        protected String loginProcessingUrl; // 기본값은 각 하위 빌더에서 설정
        protected int order = 0; // 기본 순서
        protected AuthenticationSuccessHandler successHandler;
        protected AuthenticationFailureHandler failureHandler;
        protected SecurityContextRepository securityContextRepository;

        public B loginProcessingUrl(String processingUrl) {
            Assert.hasText(processingUrl, "loginProcessingUrl cannot be empty or null");
            this.loginProcessingUrl = processingUrl;
            return self();
        }

        public B order(int order) {
            this.order = order;
            return self();
        }

        public B successHandler(AuthenticationSuccessHandler successHandler) {
            this.successHandler = successHandler; // null 허용 (기본 핸들러 사용 의미)
            return self();
        }

        public B failureHandler(AuthenticationFailureHandler failureHandler) {
            this.failureHandler = failureHandler; // null 허용 (기본 핸들러 사용 의미)
            return self();
        }

        public B securityContextRepository(SecurityContextRepository securityContextRepository) {
            this.securityContextRepository = securityContextRepository; // null 허용 (기본 저장소 사용 의미)
            return self();
        }
    }
}
