package io.springsecurity.springsecurity6x.security.core.mfa.options;

import io.springsecurity.springsecurity6x.security.core.dsl.option.AbstractOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.hibernate.query.named.AbstractNamedQueryMemento;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

public abstract class FactorAuthenticationOptions extends AbstractOptions { // AbstractOptions 상속
    private final AuthType factorType;
    // processingUrl, successHandler, failureHandler는 AbstractBuilder를 통해 설정됨
    // AbstractOptions의 필드들은 AbstractOptions.Builder를 통해 설정

    protected FactorAuthenticationOptions(AbstractNamedQueryMemento.AbstractBuilder<?,?> builder, AuthType factorType) {
        super(builder); // 부모 생성자 호출
        this.factorType = factorType;
    }

    public AuthType getFactorType() { return factorType; }

    // 이 필드들은 이제 AbstractBuilder를 통해 설정되고, AbstractOptions에 저장됨
    // 따라서 이 클래스에서 직접 필드로 가질 필요가 없음.
    // 필요하다면 getProcessingUrl() 등은 AbstractOptions의 것을 사용하거나,
    // Factor별로 특화된 URL이 있다면 여기에 추가.

    // 만약 Factor마다 고유한 processingUrl, success/failure Handler가 필요하다면,
    // 이 클래스에 필드를 두고 AbstractBuilder에서 설정하도록 해야 함.
    // 현재는 AbstractOptions의 공통 설정을 따른다고 가정.
    // 하지만 Factor별로 다른 처리 URL을 가지는 것이 일반적이므로 필드 추가
    private String processingUrl;
    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;

    // FactorOptions 생성자에서 이들을 설정하도록 변경
    protected FactorAuthenticationOptions(AbstractFactorOptionsBuilder<?,?> builder, AuthType factorType) {
        super(builder);
        this.factorType = factorType;
        this.processingUrl = builder.processingUrl;
        this.successHandler = builder.successHandler;
        this.failureHandler = builder.failureHandler;
    }

    public String getProcessingUrl() { return processingUrl; }
    public AuthenticationSuccessHandler getSuccessHandler() { return successHandler; }
    public AuthenticationFailureHandler getFailureHandler() { return failureHandler; }


    public abstract static class AbstractFactorOptionsBuilder<O extends FactorAuthenticationOptions, B extends AbstractFactorOptionsBuilder<O, B>>
            extends AbstractOptions.Builder<O, B> { // AbstractOptions.Builder 상속

        protected String processingUrl;
        protected AuthenticationSuccessHandler successHandler;
        protected AuthenticationFailureHandler failureHandler;

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
        // self()와 build()는 구체적인 하위 빌더에서 구현
    }
}
