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
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.ConversionService;
import org.springframework.format.support.FormattingConversionService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;

import java.util.ArrayList;
import java.util.List;

@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({ ASEPFilter.class, HttpSecurity.class, SecurityFilterChain.class })
public class AsepAutoConfiguration {

    private final HttpMessageConverters httpMessageConverters;
    private final ConversionService conversionService;
    // ApplicationContext is automatically available to beans that implement ApplicationContextAware
    // private final ApplicationContext applicationContext;


    public AsepAutoConfiguration(ObjectProvider<HttpMessageConverters> httpMessageConvertersProvider,
                                 ObjectProvider<ConversionService> conversionServiceProvider
            /*, ApplicationContext applicationContext */ ) {
        this.httpMessageConverters = httpMessageConvertersProvider.getIfAvailable(() -> new HttpMessageConverters(new ArrayList<>()));
        this.conversionService = conversionServiceProvider.getIfAvailable(FormattingConversionService::new);
        // this.applicationContext = applicationContext;
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
        SecurityExceptionHandlerMethodRegistry registry = new SecurityExceptionHandlerMethodRegistry();
        // ApplicationContextAware and InitializingBean interfaces handle initialization
        return registry;
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
                                 SecurityExceptionHandlerInvoker invoker) {
        return new ASEPFilter(registry, invoker, this.httpMessageConverters.getConverters());
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 10)
    @ConditionalOnMissingBean(name = "asepSecurityFilterChain")
    public SecurityFilterChain asepSecurityFilterChain(HttpSecurity http, ASEPFilter asepFilter) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // Default disable for easier testing/API usage
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll() // Default permit all, to be overridden by user config
                )
                // Add ASEPFilter after SecurityContext is established
                .addFilterAfter(asepFilter, SecurityContextHolderFilter.class);
        // For Spring Security 6+, consider SecurityContextPersistenceFilter.class:
        // .addFilterAfter(asepFilter, SecurityContextPersistenceFilter.class);

        return http.build();
    }
}