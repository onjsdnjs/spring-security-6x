package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.asep.filter.ASEPFilter;
import io.springsecurity.springsecurity6x.security.core.asep.handler.SecurityExceptionHandlerInvoker;
import io.springsecurity.springsecurity6x.security.core.asep.handler.SecurityExceptionHandlerMethodRegistry;
import io.springsecurity.springsecurity6x.security.core.asep.handler.argumentresolver.SecurityHandlerMethodArgumentResolver;
import io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig;
import io.springsecurity.springsecurity6x.security.core.config.PlatformConfig;
import io.springsecurity.springsecurity6x.security.core.context.FlowContext;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.core.dsl.common.SafeHttpCustomizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.context.SecurityContextHolderFilter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 글로벌 HTTP 보안 설정을 적용하고, 모든 SecurityFilterChain에 ASEPFilter를 동적으로 추가합니다.
 */
@Slf4j
public class GlobalConfigurer implements SecurityConfigurer {

    private final SecurityExceptionHandlerMethodRegistry methodRegistry;
    private final List<SecurityHandlerMethodArgumentResolver> defaultArgumentResolvers;
    private final List<SecurityHandlerMethodReturnValueHandler> defaultReturnValueHandlers;
    private final HttpMessageConverters httpMessageConverters;

    @Autowired
    public GlobalConfigurer(
            SecurityExceptionHandlerMethodRegistry methodRegistry,
            @Qualifier("asepDefaultArgumentResolvers") List<SecurityHandlerMethodArgumentResolver> defaultArgumentResolvers,
            @Qualifier("asepDefaultReturnValueHandlers") List<SecurityHandlerMethodReturnValueHandler> defaultReturnValueHandlers,
            HttpMessageConverters httpMessageConverters) {
        this.methodRegistry = methodRegistry;
        this.defaultArgumentResolvers = defaultArgumentResolvers != null ? defaultArgumentResolvers : Collections.emptyList();
        this.defaultReturnValueHandlers = defaultReturnValueHandlers != null ? defaultReturnValueHandlers : Collections.emptyList();
        this.httpMessageConverters = httpMessageConverters;
    }

    @Override
    public void init(PlatformContext platformCtx, PlatformConfig config) {
        log.info("GlobalConfigurer initialized. ASEP components will be configured per HttpSecurity instance.");
    }

    @Override
    public void configure(FlowContext ctx) {
        HttpSecurity http = ctx.http(); // FlowContext에서 HttpSecurity 객체를 직접 가져옴
        AuthenticationFlowConfig flow = ctx.flow();
        String dslScopeIdentifier = flow.getTypeName(); // 또는 flow.name(), flow.getFlowId() 등

        log.debug("Configuring ASEP for flow scope: {}", dslScopeIdentifier);

        List<SecurityHandlerMethodArgumentResolver> customArgumentResolvers = new ArrayList<>();
        List<SecurityHandlerMethodReturnValueHandler> customReturnValueHandlers = new ArrayList<>();

        // --- 각 DSL 스코프에 맞는 Settings 클래스 타입으로 sharedObject 조회 ---
        // 이 부분은 플랫폼의 DSL 구조와 각 DSL Configurer가 정의한 Settings 클래스 타입에 따라
        // 명시적으로 분기하거나, 리플렉션 또는 다른 메커니즘을 사용하여 동적으로 처리해야 합니다.
        // 여기서는 몇 가지 주요 DSL에 대한 예시만 포함합니다. 실제 플랫폼의 모든 DSL을 커버해야 합니다.

        // 예시: 각 DSL Configurer가 자신만의 AsepSettings 클래스를 HttpSecurity에 저장했다고 가정
        // 실제 Settings 클래스명과 패키지는 플랫폼 구현에 따라 달라집니다.
        // com.example.asep.dsl.XxxAsepSettings 와 같은 형태로 가정하고 진행합니다.

        // FormLogin DSL 스코프의 커스텀 설정 로드 (가상 클래스명 사용)
        // FormLoginAsepSettings formSettings = http.getSharedObject(FormLoginAsepSettings.class);
        // if (formSettings != null) {
        //     customArgumentResolvers.addAll(formSettings.getCustomArgumentResolvers());
        //     customReturnValueHandlers.addAll(formSettings.getCustomReturnValueHandlers());
        // }

        // Rest DSL 스코프의 커스텀 설정 로드 (가상 클래스명 사용)
        // RestAsepSettings restSettings = http.getSharedObject(RestAsepSettings.class);
        // if (restSettings != null) {
        //     customArgumentResolvers.addAll(restSettings.getCustomArgumentResolvers());
        //     customReturnValueHandlers.addAll(restSettings.getCustomReturnValueHandlers());
        // }

        // OttAsepSettings, PasskeyAsepSettings, MfaAsepSettings 등도 유사하게 처리...

        // **중요**: 위 코드는 각 DSL별 Settings 클래스가 정의되어 있고,
        // 해당 DSL Configurer가 그 타입으로 HttpSecurity에 sharedObject를 저장했을 때 동작합니다.
        // 만약 단일 Map<Class<?>, Object> 등으로 sharedObject를 관리하고 있다면,
        // dslScopeIdentifier를 사용하여 해당 Map에서 적절한 Settings 객체를 찾아야 합니다.
        // 이 부분은 플랫폼의 DSL 확장 방식과 밀접하게 연관됩니다.
        // 현재로서는 이 로직을 일반화하기 어려우므로, 각 DSL Configurer가
        // 고유 타입으로 저장하고, GlobalConfigurer가 이를 인지하여 조회하는 패턴을 권장합니다.
        // 설명을 위해 일단 custom 리스트가 비어있다고 가정하고 다음 로직으로 넘어갑니다.
        // 실제 구현 시에는 위 주석 처리된 부분과 같이 각 DSL 스코프별로 설정을 가져오는 로직이 필요합니다.
        log.debug("No DSL-specific custom ASEP resolvers/handlers found for flow [{}]. Using defaults.", dslScopeIdentifier);


        // --- 최종 Resolver/Handler 리스트 구성 (커스텀 + 기본, 커스텀 우선, 정렬) ---
        // 1. 커스텀 Resolver 추가 (우선순위 높게)
        List<SecurityHandlerMethodArgumentResolver> finalArgumentResolvers = new ArrayList<>(customArgumentResolvers);
        // 2. 기본 Resolver 중 커스텀과 중복되지 않는 것 추가
        this.defaultArgumentResolvers.stream()
                .filter(defaultResolver -> customArgumentResolvers.stream()
                        .noneMatch(customResolver -> customResolver.getClass().equals(defaultResolver.getClass())))
                .forEach(finalArgumentResolvers::add);
        AnnotationAwareOrderComparator.sort(finalArgumentResolvers); // @Order 값에 따라 정렬

        List<SecurityHandlerMethodReturnValueHandler> finalReturnValueHandlers = new ArrayList<>();
        finalReturnValueHandlers.addAll(customReturnValueHandlers);
        this.defaultReturnValueHandlers.stream()
                .filter(defaultHandler -> customReturnValueHandlers.stream()
                        .noneMatch(customHandler -> customHandler.getClass().equals(defaultHandler.getClass())))
                .forEach(finalReturnValueHandlers::add);
        AnnotationAwareOrderComparator.sort(finalReturnValueHandlers);

        log.debug("Final ArgumentResolvers for flow [{}]: Count = {}", dslScopeIdentifier, finalArgumentResolvers.size());
        log.trace("Final ArgumentResolvers for flow [{}]: {}", dslScopeIdentifier, finalArgumentResolvers);
        log.debug("Final ReturnValueHandlers for flow [{}]: Count = {}", dslScopeIdentifier, finalReturnValueHandlers.size());
        log.trace("Final ReturnValueHandlers for flow [{}]: {}", dslScopeIdentifier, finalReturnValueHandlers);

        // --- AsepHandlerAdapter 및 ASEPFilter POJO 생성 및 추가 ---
        SecurityExceptionHandlerInvoker handlerAdapter = new SecurityExceptionHandlerInvoker(finalArgumentResolvers, finalReturnValueHandlers);

        List<HttpMessageConverter<?>> converters = this.httpMessageConverters != null ?
                this.httpMessageConverters.getConverters() : Collections.emptyList();
        if (converters.isEmpty()) {
            log.warn("HttpMessageConverter list is empty for flow [{}]. ASEPFilter might not work as expected for body responses.", dslScopeIdentifier);
        }

        ASEPFilter asepFilter = new ASEPFilter(this.methodRegistry, handlerAdapter, converters);
        // ASEPFilter의 순서는 Ordered 인터페이스와 GlobalConfigurer의 순서에 의해 결정될 수 있음.
        // 필요시 asepFilter.setOrder(...) 호출

        try {
            http.addFilterAfter(asepFilter, SecurityContextHolderFilter.class);
            // 또는 Spring Security 6+ 에서는 SecurityContextPersistenceFilter.class 사용 권장
            // http.addFilterAfter(asepFilter, SecurityContextPersistenceFilter.class);
            log.info("ASEPFilter successfully added to HttpSecurity for flow: {}", dslScopeIdentifier);
        } catch (Exception e) {
            log.error("Failed to add ASEPFilter for flow [{}]. ASEP will not be active for this flow.", dslScopeIdentifier, e);
        }

        // --- 기존 플랫폼 Global Customizer 로직 실행 ---
        SafeHttpCustomizer<HttpSecurity> globalCustomizer = ctx.config().getGlobalCustomizer();
        if (globalCustomizer != null) {
            try {
                globalCustomizer.customize(http);
            } catch (Exception ex) {
                log.warn("Platform's global customizer failed for flow [{}]: {}", dslScopeIdentifier, ex);
            }
        }
    }

    @Override
    public int getOrder() {
        // 다른 주요 설정이 적용된 후, 하지만 HttpSecurity.build() 직전에 ASEPFilter를 추가하도록
        // 적절한 순서를 설정합니다. 플랫폼의 다른 SecurityConfigurer 구현체들과의 순서를 고려해야 합니다.
        return Ordered.HIGHEST_PRECEDENCE + 500; // 예시 값, 플랫폼의 다른 Configurer보다 늦게 실행되도록 조정
    }
}

