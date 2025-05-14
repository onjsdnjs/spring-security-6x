package io.springsecurity.springsecurity6x.security.core.mfa.options;

import io.springsecurity.springsecurity6x.security.core.dsl.option.AbstractOptions;
import lombok.Getter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

import java.util.Objects;

/**
 * 모든 MFA Factor 옵션들의 기본 추상 클래스.
 * 공통적으로 처리 URL, 성공/실패 핸들러, 다음 타겟 URL 등을 가질 수 있습니다.
 */
@Getter
public abstract class FactorAuthenticationOptions extends AbstractOptions {
    private final String processingUrl; // 각 Factor의 주된 인증 처리/제출 URL
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;
    private final String targetUrl; // 인증 단계 성공 후 다음으로 이동할 URL (MFA의 중간 단계 등)

    protected FactorAuthenticationOptions(AbstractFactorOptionsBuilder<?, ?> builder) {
        super(builder); // AbstractOptions의 생성자 호출 (rawHttpCustomizer 등 공통 설정)
        this.processingUrl = Objects.requireNonNull(builder.processingUrl, "processingUrl cannot be null for FactorAuthenticationOptions");
        this.successHandler = builder.successHandler;
        this.failureHandler = builder.failureHandler;
        this.targetUrl = builder.targetUrl;
    }

    // 모든 Factor Options Builder의 기본이 되는 추상 빌더
    public abstract static class AbstractFactorOptionsBuilder<T extends FactorAuthenticationOptions, B extends AbstractFactorOptionsBuilder<T, B>>
            extends AbstractOptions.Builder<T, B> {

        protected String processingUrl; // 각 Factor 구현체가 구체적인 기본값을 설정
        protected AuthenticationSuccessHandler successHandler;
        protected AuthenticationFailureHandler failureHandler;
        protected String targetUrl = "/"; // 기본 타겟 URL

        public B processingUrl(String processingUrl) {
            Assert.hasText(processingUrl, "processingUrl cannot be empty");
            this.processingUrl = processingUrl;
            return self();
        }

        public B successHandler(AuthenticationSuccessHandler successHandler) {
            this.successHandler = successHandler;
            return self();
        }

        public B failureHandler(AuthenticationFailureHandler failureHandler) {
            this.failureHandler = failureHandler;
            return self();
        }

        public B targetUrl(String targetUrl) {
            this.targetUrl = targetUrl;
            return self();
        }

        @Override
        public abstract T build(); // 하위 빌더에서 구체적으로 구현
    }
}
