package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.filter.MfaRestAuthenticationFilter;
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
import org.springframework.util.StringUtils;

public final class MfaRestAuthenticationConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractHttpConfigurer<MfaRestAuthenticationConfigurer<H>, H> {

    private String loginProcessingUrl = "/api/auth/login"; // 기본값
    private RequestMatcher requestMatcher;
    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private SecurityContextRepository securityContextRepository;
    private String mfaInitiateUrl;

    public MfaRestAuthenticationConfigurer() {
        this.requestMatcher = new ParameterRequestMatcher(this.loginProcessingUrl, HttpMethod.POST.name());
    }

    @Override
    public void init(H http) throws Exception {
        // PlatformContext 에서 AuthContextProperties를 가져와 mfaInitiateUrl 기본값 설정
        PlatformContext platformContext = http.getSharedObject(PlatformContext.class);
        if (platformContext != null) {
            AuthContextProperties authProps = platformContext.getShared(AuthContextProperties.class);
            // AuthContextProperties에 mfa.initiateUrl 같은 프로퍼티가 정의되어 있다고 가정
            if (authProps != null && authProps.getMfa() != null && StringUtils.hasText(authProps.getMfa().getInitiateUrl())) {
                this.mfaInitiateUrl = authProps.getMfa().getInitiateUrl();
            }
        }
        // mfaInitiateUrl이 설정되지 않았다면 기본값 또는 예외 처리
        if (this.mfaInitiateUrl == null) {
            this.mfaInitiateUrl = "/mfa"; // 기본값 설정
            // 또는 Assert.state(this.mfaInitiateUrl != null, "MFA initiate URL must be configured.");
        }
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
        Assert.notNull(this.mfaInitiateUrl, "mfaInitiateUrl must be configured or have a default value.");

        MfaRestAuthenticationFilter restFilter = new MfaRestAuthenticationFilter(authenticationManager, applicationContext,properties, requestMatcher);

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

    public MfaRestAuthenticationConfigurer<H> loginProcessingUrl(String loginProcessingUrl) {
        Assert.hasText(loginProcessingUrl, "loginProcessingUrl must not be null or empty");
        this.loginProcessingUrl = loginProcessingUrl;
        this.requestMatcher = new ParameterRequestMatcher(this.loginProcessingUrl, HttpMethod.POST.name());
        return this;
    }

    public MfaRestAuthenticationConfigurer<H> successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }

    public MfaRestAuthenticationConfigurer<H> failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }

    public MfaRestAuthenticationConfigurer<H> securityContextRepository(SecurityContextRepository repository) {
        this.securityContextRepository = repository;
        return this;
    }

    public MfaRestAuthenticationConfigurer<H> mfaInitiateUrl(String mfaInitiateUrl) {
        Assert.hasText(mfaInitiateUrl, "mfaInitiateUrl must not be empty");
        this.mfaInitiateUrl = mfaInitiateUrl;
        return this;
    }
}