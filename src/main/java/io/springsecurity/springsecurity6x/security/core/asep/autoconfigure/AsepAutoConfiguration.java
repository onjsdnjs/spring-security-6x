package io.springsecurity.springsecurity6x.security.core.asep.autoconfigure;

import io.springsecurity.springsecurity6x.security.core.asep.handler.SecurityExceptionHandlerMethodRegistry;
import io.springsecurity.springsecurity6x.security.core.asep.handler.argumentresolver.*;
import io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler.RedirectReturnValueHandler;
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
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.core.convert.ConversionService;
import org.springframework.format.support.FormattingConversionService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.ArrayList;
import java.util.List;

@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({ HttpSecurity.class }) // ASEPFilter 등을 직접 조건에 넣지 않음
public class AsepAutoConfiguration {

    private final HttpMessageConverters httpMessageConverters; // Boot가 제공하는 Converters
    private final ConversionService conversionService;

    public AsepAutoConfiguration(ObjectProvider<HttpMessageConverters> httpMessageConvertersProvider,
                                 ObjectProvider<ConversionService> conversionServiceProvider) {
        this.httpMessageConverters = httpMessageConvertersProvider.getIfAvailable(() -> new HttpMessageConverters(new ArrayList<>()));
        this.conversionService = conversionServiceProvider.getIfAvailable(FormattingConversionService::new);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityExceptionHandlerMethodRegistry securityExceptionHandlerMethodRegistry() {
        return new SecurityExceptionHandlerMethodRegistry();
    }

    // --- ASEP 기본 POJO Resolver/Handler 제공 빈 ---
    @Bean
    @ConditionalOnMissingBean(name = "asepDefaultArgumentResolvers")
    public List<SecurityHandlerMethodArgumentResolver> asepDefaultArgumentResolvers() {
        List<SecurityHandlerMethodArgumentResolver> resolvers = new ArrayList<>();
        resolvers.add(new CaughtExceptionArgumentResolver());
        resolvers.add(new AuthenticationObjectArgumentResolver());
        resolvers.add(new HttpServletRequestArgumentResolver());
        resolvers.add(new HttpServletResponseArgumentResolver());
        resolvers.add(new SecurityPrincipalArgumentResolver());
        resolvers.add(new SecurityRequestHeaderArgumentResolver(this.conversionService));
        resolvers.add(new SecurityCookieValueArgumentResolver(this.conversionService));
        resolvers.add(new SecurityRequestAttributeArgumentResolver());
        resolvers.add(new SecuritySessionAttributeArgumentResolver());
        resolvers.add(new SecurityRequestBodyArgumentResolver(this.httpMessageConverters.getConverters()));

        // 우선순위가 중요하다면 여기서 정렬 (또는 각 Resolver에 @Order 부여 후 Invoker에서 정렬)
        AnnotationAwareOrderComparator.sort(resolvers);
        return resolvers;
    }

    @Bean
    @ConditionalOnMissingBean(name = "asepDefaultReturnValueHandlers")
    public List<SecurityHandlerMethodReturnValueHandler> asepDefaultReturnValueHandlers() {
        List<SecurityHandlerMethodReturnValueHandler> handlers = new ArrayList<>();
        handlers.add(new ResponseEntityReturnValueHandler(this.httpMessageConverters.getConverters())); // ResponseEntity 우선 처리
        handlers.add(new SecurityResponseBodyReturnValueHandler(this.httpMessageConverters.getConverters()));
        handlers.add(new RedirectReturnValueHandler());

        // 우선순위가 중요하다면 여기서 정렬
        AnnotationAwareOrderComparator.sort(handlers);
        return handlers;
    }
}