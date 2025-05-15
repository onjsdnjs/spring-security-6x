package io.springsecurity.springsecurity6x.security.core.dsl.option;

import lombok.Getter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;

@Getter
public abstract class AuthenticationProcessingOptions extends AbstractOptions {
    private final String loginProcessingUrl;
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;
    private final SecurityContextRepository securityContextRepository;

    protected AuthenticationProcessingOptions(AbstractAuthenticationProcessingOptionsBuilder<?, ?> builder) {
        super(builder);
        this.loginProcessingUrl = builder.loginProcessingUrl;
        this.successHandler = builder.successHandler;
        this.failureHandler = builder.failureHandler;
        this.securityContextRepository = builder.securityContextRepository;
    }

    public abstract static class AbstractAuthenticationProcessingOptionsBuilder
            <O extends AuthenticationProcessingOptions, B extends AbstractAuthenticationProcessingOptionsBuilder<O, B>>
            extends AbstractOptions.Builder<O, B> {

        protected String loginProcessingUrl;
        protected AuthenticationSuccessHandler successHandler;
        protected AuthenticationFailureHandler failureHandler;
        protected SecurityContextRepository securityContextRepository;

        public B loginProcessingUrl(String processingUrl) {
            Assert.hasText(processingUrl, "processingUrl cannot be empty");
            this.loginProcessingUrl = processingUrl;
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

        public B securityContextRepository(SecurityContextRepository securityContextRepository) {
            this.securityContextRepository = securityContextRepository;
            return self();
        }
    }
}
