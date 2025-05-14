package io.springsecurity.springsecurity6x.security.core.mfa.options;

import io.springsecurity.springsecurity6x.security.core.dsl.option.AbstractOptions;
import io.springsecurity.springsecurity6x.security.enums.AuthType;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.Assert;

public abstract class FactorAuthenticationOptions extends AbstractOptions {
    private final AuthType factorType;
    private final String processingUrl;
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;

    protected FactorAuthenticationOptions(AbstractFactorOptionsBuilder<?, ?> builder, AuthType factorType) {
        super(builder); // AbstractOptions의 Builder를 받는 생성자 호출
        this.factorType = factorType;
        this.processingUrl = builder.processingUrl;
        this.successHandler = builder.successHandler;
        this.failureHandler = builder.failureHandler;
    }

    public AuthType getFactorType() { return factorType; }
    public String getProcessingUrl() { return processingUrl; }
    public AuthenticationSuccessHandler getSuccessHandler() { return successHandler; }
    public AuthenticationFailureHandler getFailureHandler() { return failureHandler; }

    public abstract static class AbstractFactorOptionsBuilder<O extends FactorAuthenticationOptions, B extends AbstractFactorOptionsBuilder<O, B>>
            extends AbstractOptions.Builder<O, B> {

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
