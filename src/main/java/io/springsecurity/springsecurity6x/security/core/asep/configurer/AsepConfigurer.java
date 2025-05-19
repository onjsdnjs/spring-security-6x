package io.springsecurity.springsecurity6x.security.core.asep.configurer;

import io.springsecurity.springsecurity6x.security.core.asep.dsl.BaseAsepAttributes;
import io.springsecurity.springsecurity6x.security.core.asep.filter.ASEPFilter;
import io.springsecurity.springsecurity6x.security.core.asep.handler.SecurityExceptionHandlerInvoker;
import io.springsecurity.springsecurity6x.security.core.asep.handler.SecurityExceptionHandlerMethodRegistry;
import io.springsecurity.springsecurity6x.security.core.asep.handler.argumentresolver.SecurityHandlerMethodArgumentResolver;
import io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;
import io.springsecurity.springsecurity6x.security.core.bootstrap.configurer.SecurityConfigurer;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.context.SecurityContextHolderFilter;

import java.util.*;
import java.util.stream.Collectors;

/**
 * ASEP (Aetherius Security Exception Protocol) 설정을 담당하는 SecurityConfigurer 구현체.
 * 이 Configurer는 싱글톤 빈으로 등록되며, 각 SecurityFilterChain(FlowContext)에 대해
 * ASEPFilter를 동적으로 구성하고 추가합니다.
 */
@Slf4j
public final class AsepConfigurer implements SecurityConfigurer {

    private final SecurityExceptionHandlerMethodRegistry methodRegistry;
    private final List<SecurityHandlerMethodArgumentResolver> defaultArgumentResolvers;
    private final List<SecurityHandlerMethodReturnValueHandler> defaultReturnValueHandlers;
    private final List<HttpMessageConverter<?>> messageConverters;
    private final Map<String, Class<? extends BaseAsepAttributes>> dslAttributesMapping;
    private int order; // Configurer 실행 순서

    public AsepConfigurer(
            SecurityExceptionHandlerMethodRegistry methodRegistry,
            List<SecurityHandlerMethodArgumentResolver> defaultArgumentResolvers,
            List<SecurityHandlerMethodReturnValueHandler> defaultReturnValueHandlers,
            HttpMessageConverters httpMessageConverters, // Spring Boot의 HttpMessageConverters 사용
            Map<String, Class<? extends BaseAsepAttributes>> dslAttributesMapping) {

        this.methodRegistry = Objects.requireNonNull(methodRegistry, "SecurityExceptionHandlerMethodRegistry cannot be null");
        this.defaultArgumentResolvers = defaultArgumentResolvers != null ? List.copyOf(defaultArgumentResolvers) : Collections.emptyList();
        this.defaultReturnValueHandlers = defaultReturnValueHandlers != null ? List.copyOf(defaultReturnValueHandlers) : Collections.emptyList();
        this.messageConverters = Objects.requireNonNull(httpMessageConverters, "HttpMessageConverters cannot be null").getConverters();
        this.dslAttributesMapping = dslAttributesMapping != null ? Map.copyOf(dslAttributesMapping) : Collections.emptyMap();
        this.order = Ordered.LOWEST_PRECEDENCE - 1000; // 기본 순서값 (다른 Configurer보다 약간 높은 우선순위로 늦게 적용)

        if (this.messageConverters.isEmpty()) {
            log.warn("ASEP: HttpMessageConverter list is empty in AsepConfigurer. Body processing for ASEP responses may not work as expected.");
        }
        if (this.dslAttributesMapping.isEmpty()) {
            log.warn("ASEP: dslAttributesMapping is empty. DSL-specific ASEP settings cannot be loaded, only defaults will apply.");
        }
    }

    /**
     * 플랫폼의 SecurityConfigurerProvider 또는 AsepAutoConfiguration에서 이 Configurer의 순서를 설정할 수 있도록 합니다.
     * @param order Configurer 실행 순서
     * @return this (for chaining)
     */
    public AsepConfigurer order(int order) {
        this.order = order;
        return this;
    }

    @Override
    public void init(PlatformContext platformContext, PlatformConfig platformConfig) {
        // 이 Configurer는 싱글톤 빈이므로, init은 애플리케이션 시작 시 한 번 호출됩니다.
        // 이 시점에서는 아직 특정 HttpSecurity 스코프의 정보가 없습니다.
        // 필요한 전역적인 초기화 로직이 있다면 여기에 추가합니다.
        log.info("ASEP: AsepConfigurer (Singleton Bean) initialized by Platform. Effective order: {}. Default Resolvers: {}, Default Handlers: {}. Mappings: {}",
                this.order, this.defaultArgumentResolvers.size(), this.defaultReturnValueHandlers.size(), this.dslAttributesMapping.size());
    }

    @Override
    public void configure(FlowContext flowCtx) throws Exception {
        Objects.requireNonNull(flowCtx, "FlowContext cannot be null");
        HttpSecurity http = Objects.requireNonNull(flowCtx.http(), "HttpSecurity from FlowContext cannot be null");
        AuthenticationFlowConfig flow = Objects.requireNonNull(flowCtx.flow(), "AuthenticationFlowConfig from FlowContext cannot be null");
        String dslScopeIdentifier = Objects.requireNonNull(flow.getTypeName(), "DSL Scope Identifier (flow.getTypeName()) cannot be null");

        log.debug("ASEP: Applying AsepConfigurer to flow: {} (HttpSecurity hash: {})", dslScopeIdentifier, http.hashCode());

        List<SecurityHandlerMethodArgumentResolver> collectedCustomArgumentResolvers = new ArrayList<>();
        List<SecurityHandlerMethodReturnValueHandler> collectedCustomReturnValueHandlers = new ArrayList<>();

        // 1. 현재 DSL 스코프의 커스텀 설정 로드
        Class<? extends BaseAsepAttributes> attributesClassKey = this.dslAttributesMapping.get(dslScopeIdentifier);
        if (attributesClassKey != null) {
            Object attributesObject = http.getSharedObject(attributesClassKey);
            if (attributesObject instanceof BaseAsepAttributes castedAttrs) {
                collectedCustomArgumentResolvers.addAll(castedAttrs.getCustomArgumentResolvers());
                collectedCustomReturnValueHandlers.addAll(castedAttrs.getCustomReturnValueHandlers());
                log.info("ASEP: Loaded user-defined ASEP customizations from {} for flow [{}]. ArgResolvers: {}, RetValHandlers: {}",
                        attributesClassKey.getSimpleName(), dslScopeIdentifier,
                        castedAttrs.getCustomArgumentResolvers().size(), castedAttrs.getCustomReturnValueHandlers().size());
            } else if (attributesObject != null) {
                log.warn("ASEP: Retrieved attributes object of type {} for scope [{}] but it does not implement BaseAsepAttributes. Customizations not loaded for this specific scope.",
                        attributesObject.getClass().getName(), dslScopeIdentifier);
            } else {
                log.debug("ASEP: No ASEP attributes object (type: {}) found in sharedObjects for DSL scope [{}]. No custom settings for this specific scope.",
                        attributesClassKey.getSimpleName(), dslScopeIdentifier);
            }
        } else {
            log.debug("ASEP: No ASEP attributes class mapping found for DSL scope identifier: [{}]. No custom settings for this specific scope.", dslScopeIdentifier);
        }

        // 2. MFA Factor의 경우, MFA 전체("mfa") 설정 병합 (Factor 설정 우선)
        if (dslScopeIdentifier.startsWith("mfa-") && !dslScopeIdentifier.equals("mfa")) { // "mfa-" 접두사로 Factor 식별
            Class<? extends BaseAsepAttributes> globalMfaAttributesClassKey = this.dslAttributesMapping.get("mfa");
            if (globalMfaAttributesClassKey != null) {
                Object globalMfaAttributesObject = http.getSharedObject(globalMfaAttributesClassKey);
                if (globalMfaAttributesObject instanceof BaseAsepAttributes globalMfaAttrs) {
                    log.info("ASEP: Found global MFA ASEP settings from {} for factor flow [{}]. Attempting to merge...",
                            globalMfaAttributesClassKey.getSimpleName(), dslScopeIdentifier);

                    // 글로벌 MFA ArgumentResolvers 중 Factor에 없는 것만 추가
                    globalMfaAttrs.getCustomArgumentResolvers().stream()
                            .filter(globalRes -> collectedCustomArgumentResolvers.stream()
                                    .noneMatch(factorRes -> factorRes.getClass().equals(globalRes.getClass())))
                            .forEach(collectedCustomArgumentResolvers::add);

                    // 글로벌 MFA ReturnValueHandlers 중 Factor에 없는 것만 추가
                    globalMfaAttrs.getCustomReturnValueHandlers().stream()
                            .filter(globalHandler -> collectedCustomReturnValueHandlers.stream()
                                    .noneMatch(factorHandler -> factorHandler.getClass().equals(globalHandler.getClass())))
                            .forEach(collectedCustomReturnValueHandlers::add);
                    log.info("ASEP: Merged global MFA ASEP settings into factor-specific settings for flow [{}]. Total custom argResolvers: {}, retValHandlers: {}",
                            dslScopeIdentifier, collectedCustomArgumentResolvers.size(), collectedCustomReturnValueHandlers.size());
                }
            }
        }

        // --- 최종 Resolver/Handler 리스트 구성 (병합된 커스텀 + 기본, 커스텀 우선, 정렬) ---
        List<SecurityHandlerMethodArgumentResolver> finalArgumentResolvers = new ArrayList<>(collectedCustomArgumentResolvers);
        this.defaultArgumentResolvers.stream()
                .filter(defaultRes -> collectedCustomArgumentResolvers.stream().noneMatch(customRes -> customRes.getClass().equals(defaultRes.getClass())))
                .forEach(finalArgumentResolvers::add);
        AnnotationAwareOrderComparator.sort(finalArgumentResolvers);

        List<SecurityHandlerMethodReturnValueHandler> finalReturnValueHandlers = new ArrayList<>(collectedCustomReturnValueHandlers);
        this.defaultReturnValueHandlers.stream()
                .filter(defaultHandler -> collectedCustomReturnValueHandlers.stream().noneMatch(customHandler -> customHandler.getClass().equals(defaultHandler.getClass())))
                .forEach(finalReturnValueHandlers::add);
        AnnotationAwareOrderComparator.sort(finalReturnValueHandlers);

        if (log.isDebugEnabled()) {
            log.debug("ASEP: Final ArgumentResolvers for flow [{}]: Count = {}. List: {}", dslScopeIdentifier, finalArgumentResolvers.size(),
                    finalArgumentResolvers.stream().map(r -> r.getClass().getSimpleName()).collect(Collectors.toList()));
            log.debug("ASEP: Final ReturnValueHandlers for flow [{}]: Count = {}. List: {}", dslScopeIdentifier, finalReturnValueHandlers.size(),
                    finalReturnValueHandlers.stream().map(h -> h.getClass().getSimpleName()).collect(Collectors.toList()));
        }

        // --- AsepHandlerAdapter 및 ASEPFilter POJO 생성 및 추가 ---
        // 이들은 각 FlowContext(HttpSecurity 인스턴스)마다 새로 생성되어 상태를 공유하지 않음.
        SecurityExceptionHandlerInvoker handlerAdapter = new SecurityExceptionHandlerInvoker(finalArgumentResolvers, finalReturnValueHandlers);
        ASEPFilter asepFilter = new ASEPFilter(this.methodRegistry, handlerAdapter, this.messageConverters);

        // ASEPFilter의 순서 설정 (필요시). Configurer의 order보다 앞서도록 설정 가능.
        // asepFilter.setOrder(this.getOrder() - 1);

        http.addFilterAfter(asepFilter, SecurityContextHolderFilter.class);
        // http.addFilterAfter(asepFilter, SecurityContextPersistenceFilter.class); // Spring Security 6+ 권장
        log.info("ASEP: ASEPFilter (POJO) added by AsepConfigurer for flow: {} with effective filter order relative to SecurityContextHolderFilter.",
                dslScopeIdentifier);
    }

    @Override
    public int getOrder() {
        return this.order;
    }
}
