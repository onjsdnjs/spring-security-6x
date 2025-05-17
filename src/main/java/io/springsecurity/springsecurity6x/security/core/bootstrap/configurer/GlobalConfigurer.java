package io.springsecurity.springsecurity6x.security.core.bootstrap.configurer;

import io.springsecurity.springsecurity6x.security.core.asep.filter.ASEPFilter;
import io.springsecurity.springsecurity6x.security.core.asep.handler.AsepHandlerAdapter;
import io.springsecurity.springsecurity6x.security.core.asep.handler.SecurityExceptionHandlerMethodRegistry;
import io.springsecurity.springsecurity6x.security.core.asep.handler.argumentresolver.SecurityHandlerMethodArgumentResolver;
import io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;
import io.springsecurity.springsecurity6x.security.core.config.AuthenticationFlowConfig; // FlowContext에서 반환하는 타입
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
import java.util.Map; // 임시로 Map<Class<?>, Object> 사용 가능성 고려 (비권장)


/**
 * 글로벌 HTTP 보안 설정을 적용하고, 모든 SecurityFilterChain에 ASEPFilter를 동적으로 추가합니다.
 */
@Slf4j
public class GlobalConfigurer implements SecurityConfigurer {

    private final SecurityExceptionHandlerMethodRegistry methodRegistry;
    private final List<SecurityHandlerMethodArgumentResolver> defaultArgumentResolvers;
    private final List<SecurityHandlerMethodReturnValueHandler> defaultReturnValueHandlers;
    private final HttpMessageConverters httpMessageConverters;

    /**
     * 각 DSL 스코프별 ASEP 설정을 담는 컨테이너 클래스의 타입을 키로 하고,
     * 해당 설정 객체를 HttpSecurity의 sharedObjects에서 가져오기 위한 클래스 타입.
     * 실제 플랫폼에서는 이 Map을 사용하지 않고, 각 DSL Configurer가 정의한
     * 고유한 Settings 클래스 타입을 직접 사용하여 getSharedObject를 호출해야 합니다.
     * 이 Map은 어떤 타입의 Settings 객체가 존재하는지 동적으로 알아야 할 때 참고할 수 있지만,
     * 타입 안정성을 위해 직접 클래스 리터럴을 사용하는 것이 좋습니다.
     * (예: http.getSharedObject(FormLoginAsepSettings.class))
     * 여기서는 설명을 위해 개념적으로만 남겨둡니다. 실제 구현에서는 이 Map을 사용하지 않을 것입니다.
     */
    // private final Map<String, Class<? extends DslAsepSettings>> dslAsepSettingsTypes;


    @Autowired
    public GlobalConfigurer(
            SecurityExceptionHandlerMethodRegistry methodRegistry,
            @Qualifier("asepDefaultArgumentResolvers") List<SecurityHandlerMethodArgumentResolver> defaultArgumentResolvers,
            @Qualifier("asepDefaultReturnValueHandlers") List<SecurityHandlerMethodReturnValueHandler> defaultReturnValueHandlers,
            HttpMessageConverters httpMessageConverters) { // 필요시 주입
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
    @SuppressWarnings("unchecked")
    public void configure(FlowContext ctx) {
        HttpSecurity http = ctx.http();
        AuthenticationFlowConfig flow = ctx.flow();
        String dslScopeIdentifier = flow.getTypeName(); // 또는 flow.name(), flow.getFlowId() 등 고유 식별자

        log.debug("Configuring ASEP for flow scope: {}", dslScopeIdentifier);

        List<SecurityHandlerMethodArgumentResolver> customArgumentResolvers = Collections.emptyList();
        List<SecurityHandlerMethodReturnValueHandler> customReturnValueHandlers = Collections.emptyList();

        // --- HttpSecurity의 sharedObjects 에서 DSL 스코프별 ASEP 설정 가져오기 ---
        // 각 DSL Configurer (FormLoginConfigurer, RestConfigurer 등)는
        // 자신만의 고유한 Settings 클래스 타입으로 HttpSecurity에 설정을 저장해야 합니다.
        // GlobalConfigurer는 이 타입들을 알아야 하거나, 또는 FlowContext/AuthenticationFlowConfig를 통해
        // 해당 스코프의 Settings 객체를 가져올 수 있는 방법을 제공받아야 합니다.

        // 예시: AuthenticationFlowConfig에 따라 분기하여 적절한 Settings 클래스 타입으로 조회
        // 이 부분은 플랫폼의 DSL 구조와 각 DSL Configurer가 sharedObject를 어떻게 저장하는지에 따라 매우 달라짐.
        // 아래는 개념적인 예시이며, 실제로는 더 정교한 타입 매핑 또는 조회 로직이 필요.
        Object dslAsepSettingsObject = null;
        // 가상의 DSL 타입 이름 또는 클래스 이름을 사용하여 분기
        // if ("FORM_LOGIN_DSL_TYPE_NAME".equals(dslScopeIdentifier)) { // FORM_LOGIN_DSL_TYPE_NAME은 플랫폼에서 정의한 값
        // dslAsepSettingsObject = http.getSharedObject(FormLoginAsepSettings.class); // 각 DSL은 자신만의 Settings 클래스 타입을 키로 사용
        // } else if ("REST_DSL_TYPE_NAME".equals(dslScopeIdentifier)) {
        // dslAsepSettingsObject = http.getSharedObject(RestAsepSettings.class);
        // }
        // ... 기타 DSL 타입에 대한 처리 ...

        // 임시 방편: 만약 모든 DSL Configurer가 동일한 방식으로 키를 생성하여 저장한다면
        // (예: DslAsepSettingsHolder.class 타입으로 저장하고, 내부에 dslType 필드를 두는 방식)
        // 하지만 타입 안정성을 위해 각 DSL별 고유 Settings 클래스 사용 권장.

        // 지금은 플랫폼의 DSL Configurer가 구체적으로 어떻게 sharedObject를 저장하는지 알 수 없으므로,
        // 임시로 일반적인 Map<String, Object> 형태의 공유 객체를 가정하고 키로 접근 시도 (비권장, 타입 불안정)
        // **권장 방식은 각 DSL Configurer가 특정 클래스 타입으로 setSharedObject 한 것을
        // 여기서 해당 클래스 타입으로 getSharedObject 하는 것입니다.**
        // 예: FormLoginAsepSettings formSettings = http.getSharedObject(FormLoginAsepSettings.class);

        // --- 임시 코드 (실제 플랫폼 구조에 맞게 수정 필요) ---
        // 각 DSL Configurer가 "dslName.customArgumentResolvers" 와 같은 문자열 키 대신
        // 특정 클래스 타입(예: FormLoginCustomResolvers.class)을 키로 사용하여 List를 저장했다고 가정.
        // 여기서는 그 클래스 타입을 알아야 함.
        // 우선은 이전처럼 문자열 키 방식의 아이디어를 유지하되, HttpSecurity API 제약을 인지하고 있다는 주석 추가.
        // 이는 실제 구현에서는 동작하지 않으며, 타입 기반 조회로 변경되어야 함.
        Map<Class<?>, Object> sharedObjects = http.getSharedObjects(); // 내부 맵 직접 접근은 불가. getSharedObject(Class<T>) 사용해야 함.

        // **올바른 접근 방식 (각 DSL Configurer가 정의한 클래스 타입 사용):**
        // 이 예시는 개념을 보여주기 위한 것이며, 실제로는 각 DSL 타입에 맞는 Settings 클래스를 사용해야 합니다.
        // 예를 들어, FormLoginConfigurer가 FormLoginAsepCustomConfig.class 타입으로 저장했다면,
        // FormLoginAsepCustomConfig customConfig = http.getSharedObject(FormLoginAsepCustomConfig.class);
        // if (customConfig != null) {
        //     customArgumentResolvers = customConfig.getCustomArgumentResolvers();
        //     customReturnValueHandlers = customConfig.getCustomReturnValueHandlers();
        // }

        // 현재 업로드된 파일만으로는 각 DSL Configurer가 어떤 타입으로 sharedObject를 저장하는지 알 수 없으므로,
        // 이 부분은 플랫폼 설계자와 협의하여 정확한 클래스 타입을 사용하도록 수정해야 합니다.
        // 지금은 설명을 위해 customResolver/Handler가 비어있는 상태로 진행합니다.
        // (사용자가 DSL을 통해 추가한 Resolver/Handler가 있다면 이 리스트에 채워져야 함)
        log.warn("Cannot retrieve DSL-specific custom resolvers/handlers due to HttpSecurity.getSharedObject API constraints with string keys. " +
                "This part needs to be adapted based on how DSL Configurers store settings using class types as keys. Proceeding with empty custom lists for now.");


        // --- 최종 Resolver/Handler 리스트 구성 (이전 로직과 동일) ---
        List<SecurityHandlerMethodArgumentResolver> finalArgumentResolvers = new ArrayList<>(customArgumentResolvers);
        List<SecurityHandlerMethodArgumentResolver> tempCustomArgResolvers = new ArrayList<>(customArgumentResolvers); // for filtering
        this.defaultArgumentResolvers.stream()
                .filter(defaultResolver -> tempCustomArgResolvers.stream()
                        .noneMatch(customResolver -> customResolver.getClass().equals(defaultResolver.getClass())))
                .forEach(finalArgumentResolvers::add);
        AnnotationAwareOrderComparator.sort(finalArgumentResolvers);

        List<SecurityHandlerMethodReturnValueHandler> finalReturnValueHandlers = new ArrayList<>(customReturnValueHandlers);
        List<SecurityHandlerMethodReturnValueHandler> tempCustomRetValHandlers = new ArrayList<>(customReturnValueHandlers); // for filtering
        this.defaultReturnValueHandlers.stream()
                .filter(defaultHandler -> tempCustomRetValHandlers.stream()
                        .noneMatch(customHandler -> customHandler.getClass().equals(defaultHandler.getClass())))
                .forEach(finalReturnValueHandlers::add);
        AnnotationAwareOrderComparator.sort(finalReturnValueHandlers);

        log.debug("Final ArgumentResolvers for flow [{}]: {} (Custom: {}, Default: {})",
                dslScopeIdentifier, finalArgumentResolvers.size(), customArgumentResolvers.size(),
                finalArgumentResolvers.size() - customArgumentResolvers.size());
        log.debug("Final ReturnValueHandlers for flow [{}]: {} (Custom: {}, Default: {})",
                dslScopeIdentifier, finalReturnValueHandlers.size(), customReturnValueHandlers.size(),
                finalReturnValueHandlers.size() - customReturnValueHandlers.size());

        // --- AsepHandlerAdapter 및 ASEPFilter POJO 생성 및 추가 (이전 로직과 동일) ---
        AsepHandlerAdapter handlerAdapter = new AsepHandlerAdapter(finalArgumentResolvers, finalReturnValueHandlers);
        List<HttpMessageConverter<?>> converters = this.httpMessageConverters != null ?
                this.httpMessageConverters.getConverters() : Collections.emptyList();
        ASEPFilter asepFilter = new ASEPFilter(this.methodRegistry, handlerAdapter, converters);

        try {
            http.addFilterAfter(asepFilter, SecurityContextHolderFilter.class);
            log.info("ASEPFilter successfully added to HttpSecurity for flow: {}", dslScopeIdentifier);
        } catch (Exception e) {
            log.error("Failed to add ASEPFilter for flow: {}. ASEP will not be active for this flow.", dslScopeIdentifier, e);
        }

        // --- 기존 플랫폼 Global Customizer 로직 실행 (이전 로직과 동일) ---
        SafeHttpCustomizer<HttpSecurity> globalCustomizer = ctx.config().getGlobalCustomizer();
        if (globalCustomizer != null) {
            try {
                globalCustomizer.customize(http);
            } catch (Exception ex) {
                log.warn("Platform's global customizer failed for flow: {}", dslScopeIdentifier, ex);
            }
        }
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 200; // 이전과 동일하게 유지 또는 플랫폼 정책에 맞게 조정
    }
}

