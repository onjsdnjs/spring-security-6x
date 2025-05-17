package io.springsecurity.springsecurity6x.security.core.asep.autoconfigure;

import io.springsecurity.springsecurity6x.security.core.asep.filter.ASEPFilter;
import io.springsecurity.springsecurity6x.security.core.asep.handler.SecurityExceptionHandlerInvoker;
import io.springsecurity.springsecurity6x.security.core.asep.handler.SecurityExceptionHandlerMethodRegistry;
import io.springsecurity.springsecurity6x.security.core.asep.handler.argumentresolver.*;
import io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler.ResponseEntityReturnValueHandler;
import io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;
import io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler.SecurityResponseBodyReturnValueHandler;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.ConversionService;
import org.springframework.format.support.FormattingConversionService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;

@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({ ASEPFilter.class, HttpSecurity.class, SecurityFilterChain.class })
public class AsepAutoConfiguration {

    private final HttpMessageConverters httpMessageConverters;
    private final ConversionService conversionService;

    public AsepAutoConfiguration(ObjectProvider<HttpMessageConverters> httpMessageConvertersProvider,
                                 ObjectProvider<ConversionService> conversionServiceProvider) {
        this.httpMessageConverters = httpMessageConvertersProvider.getIfAvailable(() -> new HttpMessageConverters(new ArrayList<>()));
        this.conversionService = conversionServiceProvider.getIfAvailable(FormattingConversionService::new);
    }

    @Bean
    @ConditionalOnMissingBean
    public CaughtExceptionArgumentResolver caughtExceptionArgumentResolver() {
        return new CaughtExceptionArgumentResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationObjectArgumentResolver authenticationObjectArgumentResolver() {
        return new AuthenticationObjectArgumentResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public HttpServletRequestArgumentResolver httpServletRequestArgumentResolver() {
        return new HttpServletRequestArgumentResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public HttpServletResponseArgumentResolver httpServletResponseArgumentResolver() {
        return new HttpServletResponseArgumentResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityPrincipalArgumentResolver securityPrincipalArgumentResolver() {
        return new SecurityPrincipalArgumentResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityRequestHeaderArgumentResolver securityRequestHeaderArgumentResolver() {
        return new SecurityRequestHeaderArgumentResolver(this.conversionService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityCookieValueArgumentResolver securityCookieValueArgumentResolver() {
        return new SecurityCookieValueArgumentResolver(this.conversionService);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityRequestAttributeArgumentResolver securityRequestAttributeArgumentResolver() {
        return new SecurityRequestAttributeArgumentResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecuritySessionAttributeArgumentResolver securitySessionAttributeArgumentResolver() {
        return new SecuritySessionAttributeArgumentResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityRequestBodyArgumentResolver securityRequestBodyArgumentResolver() {
        return new SecurityRequestBodyArgumentResolver(this.httpMessageConverters.getConverters());
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityResponseBodyReturnValueHandler securityResponseBodyReturnValueHandler() {
        return new SecurityResponseBodyReturnValueHandler(this.httpMessageConverters.getConverters());
    }

    @Bean
    @ConditionalOnMissingBean
    public ResponseEntityReturnValueHandler responseEntityReturnValueHandler() {
        return new ResponseEntityReturnValueHandler(this.httpMessageConverters.getConverters());
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityExceptionHandlerMethodRegistry securityExceptionHandlerMethodRegistry() {
        return new SecurityExceptionHandlerMethodRegistry();
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityExceptionHandlerInvoker securityExceptionHandlerInvoker(
            List<SecurityHandlerMethodArgumentResolver> argumentResolvers,
            List<SecurityHandlerMethodReturnValueHandler> returnValueHandlers) {
        return new SecurityExceptionHandlerInvoker(argumentResolvers, returnValueHandlers);
    }

    @Bean
    @ConditionalOnMissingBean
    public ASEPFilter asepFilter(SecurityExceptionHandlerMethodRegistry registry,
                                 SecurityExceptionHandlerInvoker invoker,
                                 HttpMessageConverters httpMessageConverters) {
        return new ASEPFilter(registry, invoker, httpMessageConverters.getConverters());
    }

}