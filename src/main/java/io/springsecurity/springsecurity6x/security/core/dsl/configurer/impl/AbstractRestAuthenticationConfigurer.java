package io.springsecurity.springsecurity6x.security.core.dsl.configurer.impl;

import io.springsecurity.springsecurity6x.security.filter.BaseAuthenticationFilter;
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

import java.util.Objects;

/**
 * REST 인증 설정을 위한 추상 기반 클래스
 * 공통 기능을 제공하고 템플릿 메서드 패턴을 사용하여 확장 가능
 */
public abstract class AbstractRestAuthenticationConfigurer<T extends AbstractRestAuthenticationConfigurer<T, H>, H extends HttpSecurityBuilder<H>>
        extends AbstractHttpConfigurer<T, H> {

    protected String loginProcessingUrl = "/api/auth/login";
    protected RequestMatcher requestMatcher;
    protected AuthenticationSuccessHandler successHandler;
    protected AuthenticationFailureHandler failureHandler;
    protected SecurityContextRepository securityContextRepository;

    protected AbstractRestAuthenticationConfigurer() {
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

        // 템플릿 메서드 - 하위 클래스에서 필터 생성
        BaseAuthenticationFilter filter = createAuthenticationFilter(http, authenticationManager, applicationContext, properties);

        // 공통 설정 적용
        configureFilter(filter);

        http.addFilterBefore(postProcess(filter), UsernamePasswordAuthenticationFilter.class);
    }

    /**
     * 하위 클래스에서 구현해야 할 추상 메서드
     * 특정 타입의 인증 필터를 생성
     */
    protected abstract BaseAuthenticationFilter createAuthenticationFilter(
            H http,
            AuthenticationManager authenticationManager,
            ApplicationContext applicationContext,
            AuthContextProperties properties) throws Exception;

    /**
     * 필터에 공통 설정을 적용하는 메서드
     * 리플렉션을 사용하여 필터 타입에 관계없이 설정 적용
     */
    protected void configureFilter(BaseAuthenticationFilter filter) {

            if (successHandler != null) {
                filter.setSuccessHandler(successHandler);
            }
            if (failureHandler != null) {
                filter.setFailureHandler(failureHandler);
            }
            filter.setSecurityContextRepository(Objects.requireNonNullElseGet(securityContextRepository,
                    RequestAttributeSecurityContextRepository::new));
    }



    public T loginProcessingUrl(String loginProcessingUrl) {
        Assert.hasText(loginProcessingUrl, "loginProcessingUrl must not be null or empty");
        this.loginProcessingUrl = loginProcessingUrl;
        this.requestMatcher = new ParameterRequestMatcher(this.loginProcessingUrl, HttpMethod.POST.name());
        return (T) this;
    }

    public T successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return (T) this;
    }

    public T failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return (T) this;
    }

    public T securityContextRepository(SecurityContextRepository repository) {
        this.securityContextRepository = repository;
        return (T) this;
    }
}