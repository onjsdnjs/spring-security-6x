package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.mfa.context.ContextPersistence;
import io.springsecurity.springsecurity6x.security.core.mfa.policy.MfaPolicyProvider;
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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public final class RestAuthenticationConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractHttpConfigurer<RestAuthenticationConfigurer<H>, H> {

    private String loginProcessingUrl = "/api/auth/login"; // 기본값
    private RequestMatcher requestMatcher; // loginProcessingUrl에 따라 동적으로 설정됨
    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private SecurityContextRepository securityContextRepository;
    private String mfaInitiateUrl;

    public RestAuthenticationConfigurer() {
        this.requestMatcher = new AntPathRequestMatcher(this.loginProcessingUrl, HttpMethod.POST.name());
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

        // HttpSecurity의 공유 객체 저장소에서 ContextPersistence 와 MfaPolicyProvider 가져오기
        ContextPersistence contextPersistence = http.getSharedObject(ContextPersistence.class);
        Assert.notNull(contextPersistence, "ContextPersistence cannot be null (is it shared from HttpSecurity?)");

        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        Assert.notNull(contextPersistence, "ContextPersistence cannot be null (is it shared from HttpSecurity?)");

        MfaPolicyProvider mfaPolicyProvider = http.getSharedObject(MfaPolicyProvider.class);
        Assert.notNull(mfaPolicyProvider, "MfaPolicyProvider cannot be null (is it shared from HttpSecurity?)");

        ObjectMapper objectMapper = applicationContext.getBean(ObjectMapper.class);

        // requestMatcher가 loginProcessingUrl에 의해 설정되었는지 확인
        if (this.requestMatcher == null) {
            this.requestMatcher = new AntPathRequestMatcher(this.loginProcessingUrl, HttpMethod.POST.name());
        }
        Assert.notNull(this.mfaInitiateUrl, "mfaInitiateUrl must be configured or have a default value.");

        RestAuthenticationFilter restFilter = new RestAuthenticationFilter(
                authenticationManager,
                contextPersistence,
                applicationContext
        );

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
        this.requestMatcher = new AntPathRequestMatcher(this.loginProcessingUrl, HttpMethod.POST.name());
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

    public RestAuthenticationConfigurer<H> mfaInitiateUrl(String mfaInitiateUrl) {
        Assert.hasText(mfaInitiateUrl, "mfaInitiateUrl must not be empty");
        this.mfaInitiateUrl = mfaInitiateUrl;
        return this;
    }
}