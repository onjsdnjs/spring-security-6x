package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.filter.RestAuthenticationFilter;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.ParameterRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

public final class RestAuthenticationConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractHttpConfigurer<RestAuthenticationConfigurer<H>, H> {

    private String loginProcessingUrl = "/api/auth/login"; // 기본값
    private RequestMatcher requestMatcher;
    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private SecurityContextRepository securityContextRepository;
    private String mfaInitiateUrl;

    public RestAuthenticationConfigurer() {
        this.requestMatcher = new ParameterRequestMatcher(this.loginProcessingUrl, HttpMethod.POST.name());
    }


    @Override
    public void configure(H http) throws Exception {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        Assert.notNull(authenticationManager, "AuthenticationManager cannot be null (is it shared from HttpSecurity?)");

        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        AuthContextProperties properties = applicationContext.getBean(AuthContextProperties.class);

        if (this.requestMatcher == null) {
            this.requestMatcher = new ParameterRequestMatcher(this.loginProcessingUrl, HttpMethod.POST.name());
        }

        RestAuthenticationFilter restFilter = new RestAuthenticationFilter(requestMatcher,authenticationManager, properties);

        if (successHandler != null) {
            restFilter.setSuccessHandler(successHandler);
        }
        if (failureHandler != null) {
            restFilter.setFailureHandler(failureHandler);
        }
        if (securityContextRepository != null) {
            restFilter.setSecurityContextRepository(securityContextRepository);
        } else {
            restFilter.setSecurityContextRepository(new RequestAttributeSecurityContextRepository());
        }
        http.addFilterBefore(postProcess(restFilter), UsernamePasswordAuthenticationFilter.class);
    }

    public RestAuthenticationConfigurer<H> loginProcessingUrl(String loginProcessingUrl) {
        Assert.hasText(loginProcessingUrl, "loginProcessingUrl must not be null or empty");
        this.loginProcessingUrl = loginProcessingUrl;
        this.requestMatcher = new ParameterRequestMatcher(this.loginProcessingUrl, HttpMethod.POST.name());
        return this;
    }

    public RestAuthenticationConfigurer<H> successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }

    public RestAuthenticationConfigurer<H> failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }

    public RestAuthenticationConfigurer<H> securityContextRepository(SecurityContextRepository repository) {
        this.securityContextRepository = repository;
        return this;
    }
}