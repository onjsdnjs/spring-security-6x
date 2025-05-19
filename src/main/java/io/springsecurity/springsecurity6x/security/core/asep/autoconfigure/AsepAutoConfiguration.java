package io.springsecurity.springsecurity6x.security.core.asep.autoconfigure;

import io.springsecurity.springsecurity6x.security.core.asep.configurer.AsepConfigurer;
import io.springsecurity.springsecurity6x.security.core.asep.dsl.BaseAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.asep.dsl.FormAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.asep.handler.SecurityExceptionHandlerMethodRegistry;
import io.springsecurity.springsecurity6x.security.core.asep.handler.argumentresolver.*;
import io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler.RedirectReturnValueHandler;
import io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler.ResponseEntityReturnValueHandler;
import io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;
import io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler.SecurityResponseBodyReturnValueHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
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

import java.util.*;

@AutoConfiguration // Spring Boot 2.7+ (이전 버전은 @Configuration)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({HttpSecurity.class}) // HttpSecurity 존재 조건
@Slf4j
public class AsepAutoConfiguration {

    private final HttpMessageConverters httpMessageConverters; // final로 변경
    private final ConversionService conversionService; // final로 변경

    // 생성자 주입을 통해 Spring Boot가 자동 구성한 빈들을 가져옴
    public AsepAutoConfiguration(ObjectProvider<HttpMessageConverters> httpMessageConvertersProvider,
                                 ObjectProvider<ConversionService> conversionServiceProvider) {
        this.httpMessageConverters = httpMessageConvertersProvider.getIfAvailable(() -> new HttpMessageConverters(Collections.emptyList()));
        this.conversionService = conversionServiceProvider.getIfAvailable(FormattingConversionService::new); // 기본 FormattingConversionService
        log.info("ASEP: AsepAutoConfiguration initialized. HttpMessageConverters count: {}, ConversionService: {}",
                this.httpMessageConverters.getConverters().size(), this.conversionService.getClass().getSimpleName());
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityExceptionHandlerMethodRegistry securityExceptionHandlerMethodRegistry() {
        log.debug("ASEP: Creating SecurityExceptionHandlerMethodRegistry bean.");
        // ApplicationContextAware, InitializingBean 구현으로 Spring이 생명주기 관리
        return new SecurityExceptionHandlerMethodRegistry();
    }

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
        resolvers.add(new SecurityRequestBodyArgumentResolver(this.httpMessageConverters.getConverters())); // getConverters() 호출
        AnnotationAwareOrderComparator.sort(resolvers); // 정렬
        log.debug("ASEP: Created 'asepDefaultArgumentResolvers' bean with {} resolvers.", resolvers.size());
        return Collections.unmodifiableList(resolvers); // 불변 리스트로 반환
    }

    @Bean
    @ConditionalOnMissingBean(name = "asepDefaultReturnValueHandlers")
    public List<SecurityHandlerMethodReturnValueHandler> asepDefaultReturnValueHandlers() {
        List<SecurityHandlerMethodReturnValueHandler> handlers = new ArrayList<>();
        // 우선순위 고려: ResponseEntity가 다른 @ResponseBody보다 먼저 처리되도록 리스트 순서 조정 가능
        handlers.add(new ResponseEntityReturnValueHandler(this.httpMessageConverters.getConverters()));
        handlers.add(new SecurityResponseBodyReturnValueHandler(this.httpMessageConverters.getConverters()));
        handlers.add(new RedirectReturnValueHandler());
        AnnotationAwareOrderComparator.sort(handlers); // 정렬
        log.debug("ASEP: Created 'asepDefaultReturnValueHandlers' bean with {} handlers.", handlers.size());
        return Collections.unmodifiableList(handlers); // 불변 리스트로 반환
    }

    @Bean
    @ConditionalOnMissingBean(name = "asepDslAttributesMapping")
    public Map<String, Class<? extends BaseAsepAttributes>> asepDslAttributesMapping() {
        Map<String, Class<? extends BaseAsepAttributes>> mapping = new HashMap<>();
        // --- 중요: 이 매핑은 플랫폼의 AuthenticationFlowConfig.getTypeName() 반환값과 정확히 일치해야 합니다. ---
        mapping.put("form", FormAsepAttributes.class);
        mapping.put("rest", RestAsepAttributes.class);
        mapping.put("ott", OttAsepAttributes.class);
        mapping.put("passkey", PasskeyAsepAttributes.class);
        mapping.put("mfa", MfaAsepAttributes.class);
        mapping.put("mfa-ott", MfaOttAsepAttributes.class);
        mapping.put("mfa-passkey", MfaPasskeyAsepAttributes.class);
        // ... (플랫폼에서 추가된 다른 DSL 및 MFA Factor 타입에 대한 모든 매핑을 여기에 정확히 추가) ...

        log.info("ASEP: Initialized 'asepDslAttributesMapping' ({} entries). Keys: {}", mapping.size(), mapping.keySet());
        if (mapping.isEmpty()) {
            log.warn("ASEP: 'asepDslAttributesMapping' is EMPTY. DSL-specific ASEP settings may not load correctly if any DSL uses ASEP.");
        }
        return Collections.unmodifiableMap(mapping); // 불변 맵으로 반환
    }

    @Bean
    @ConditionalOnMissingBean
    public AsepConfigurer asepConfigurer(
            SecurityExceptionHandlerMethodRegistry methodRegistry,
            @Qualifier("asepDefaultArgumentResolvers") List<SecurityHandlerMethodArgumentResolver> defaultArgumentResolvers,
            @Qualifier("asepDefaultReturnValueHandlers") List<SecurityHandlerMethodReturnValueHandler> defaultReturnValueHandlers,
            HttpMessageConverters httpMessageConverters, // HttpMessageConverters 빈 직접 주입
            @Qualifier("asepDslAttributesMapping") Map<String, Class<? extends BaseAsepAttributes>> dslAttributesMapping) {
        AsepConfigurer configurer = new AsepConfigurer(
                methodRegistry,
                defaultArgumentResolvers,
                defaultReturnValueHandlers,
                httpMessageConverters, // AsepConfigurer 생성자에 HttpMessageConverters 객체 전달
                dslAttributesMapping
        );
        // configurer.order(플랫폼_기본_순서); // AsepConfigurer에 order 설정 메소드가 있다면 여기서 기본값 설정
        log.info("ASEP: AsepConfigurer bean (Singleton, implements SecurityConfigurer) created and configured.");
        return configurer;
    }
}