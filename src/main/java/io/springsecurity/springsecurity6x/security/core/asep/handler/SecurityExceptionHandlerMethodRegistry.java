package io.springsecurity.springsecurity6x.security.core.asep.handler;

import io.springsecurity.springsecurity6x.security.core.asep.annotation.SecurityControllerAdvice;
import io.springsecurity.springsecurity6x.security.core.asep.annotation.SecurityExceptionHandler;
import io.springsecurity.springsecurity6x.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.MethodIntrospector;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.CollectionUtils;
import org.springframework.util.ReflectionUtils.MethodFilter;
import org.springframework.web.accept.ContentNegotiationManager;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.ServletWebRequest;

import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class SecurityExceptionHandlerMethodRegistry implements ApplicationContextAware, InitializingBean {

    private ApplicationContext applicationContext;
    // 캐시: 핸들러 빈 타입 -> 해당 빈 내의 예외 처리 메소드 분석 결과 (ExceptionHandlerMethodResolver)
    private final Map<Class<?>, ExceptionHandlerMethodResolver> methodResolverCache = new ConcurrentHashMap<>(64);
    // 어드바이스 빈과 해당 빈의 ExceptionHandlerMethodResolver를 순서대로 저장 (LinkedHashMap 유지)
    private final Map<Object, ExceptionHandlerMethodResolver> adviceToResolverCache = new LinkedHashMap<>();

    private ContentNegotiationManager contentNegotiationManager;

    public SecurityExceptionHandlerMethodRegistry() {
        // 기본 ContentNegotiationManager 설정 (Accept 헤더 기반)
        this.contentNegotiationManager = new ContentNegotiationManager(new HeaderContentNegotiationStrategy());
    }

    // 외부에서 ContentNegotiationManager를 주입받을 수 있도록 setter 제공 (선택적)
    public void setContentNegotiationManager(ContentNegotiationManager contentNegotiationManager) {
        this.contentNegotiationManager = Objects.requireNonNull(contentNegotiationManager, "ContentNegotiationManager must not be null");
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(applicationContext, "ApplicationContext must not be set for SecurityExceptionHandlerMethodRegistry");
        initializeExceptionHandlerAdviceCache();
    }

    private void initializeExceptionHandlerAdviceCache() {
        if (this.applicationContext == null) {
            log.warn("ASEP: ApplicationContext is null. Cannot initialize SecurityExceptionHandlerAdviceCache.");
            return;
        }
        log.debug("ASEP: Initializing SecurityExceptionHandlerAdviceCache: Looking for @SecurityControllerAdvice beans...");

        List<Object> adviceBeans = new ArrayList<>(this.applicationContext.getBeansWithAnnotation(SecurityControllerAdvice.class).values());
        // 어드바이스 빈들을 @Order 또는 Ordered 인터페이스에 따라 정렬 (낮은 값 = 높은 우선순위)
        AnnotationAwareOrderComparator.sort(adviceBeans);

        for (Object adviceBean : adviceBeans) {
            Class<?> beanType = ClassUtils.getUserClass(adviceBean); // AOP 프록시 처리
            // TODO: @SecurityControllerAdvice의 assignableTypes, basePackages 필터링 로직 적용 필요
            //       (Spring MVC의 ControllerAdviceBean.isApplicableToBeanType 참고)

            ExceptionHandlerMethodResolver resolver = this.methodResolverCache.computeIfAbsent(beanType, ExceptionHandlerMethodResolver::new);
            if (resolver.hasExceptionMappings()) {
                this.adviceToResolverCache.put(adviceBean, resolver);
                log.debug("ASEP: Detected @SecurityExceptionHandler methods in advice bean: {}", beanType.getName());
            }
        }
        log.info("ASEP: Initialized SecurityExceptionHandlerAdviceCache with {} advice beans.", this.adviceToResolverCache.size());
    }

    @Nullable
    public HandlerMethod findBestExceptionHandlerMethod(
            Throwable exception,
            @Nullable Authentication authentication, // 현재는 사용되지 않지만, 향후 확장 가능성
            HttpServletRequest servletRequest) {

        Assert.notNull(exception, "Exception must not be null");
        Assert.notNull(servletRequest, "HttpServletRequest must not be null");

        NativeWebRequest webRequest = new ServletWebRequest(servletRequest);
        List<MediaType> acceptedMediaTypes;
        try {
            acceptedMediaTypes = this.contentNegotiationManager.resolveMediaTypes(webRequest);
            if (CollectionUtils.isEmpty(acceptedMediaTypes)) { // No concrete media type accepted
                acceptedMediaTypes = Collections.singletonList(MediaType.ALL);
            }
        } catch (Exception ex) {
            log.warn("ASEP: Could not resolve media types for request due to {}. Using MediaType.ALL.", ex.getMessage());
            acceptedMediaTypes = Collections.singletonList(MediaType.ALL);
        }

        // adviceCache는 @Order에 따라 정렬되어 있으므로, 우선순위가 높은 advice부터 순회
        for (Map.Entry<Object, ExceptionHandlerMethodResolver> entry : this.adviceToResolverCache.entrySet()) {
            Object adviceBean = entry.getKey();
            ExceptionHandlerMethodResolver resolver = entry.getValue();

            // Content Negotiation을 고려하여 최적의 메소드 찾기
            // acceptedMediaTypes는 이미 정렬되어 있음 (품질값, 구체성 순)
            for (MediaType acceptedMediaType : acceptedMediaTypes) {
                Method bestMatchingMethod = resolver.resolveMethod(exception, acceptedMediaType);
                if (bestMatchingMethod != null) {
                    SecurityExceptionHandler ann = AnnotatedElementUtils.findMergedAnnotation(bestMatchingMethod, SecurityExceptionHandler.class);
                    // 어노테이션이 없다면 이 로직에 걸리지 않았을 것이므로 null 가능성은 낮음
                    String[] produces = (ann != null) ? ann.produces() : new String[0];
                    int priority = (ann != null) ? ann.priority() : Ordered.LOWEST_PRECEDENCE;
                    Class<? extends Throwable>[] handledExceptions = (ann != null && ann.value().length > 0) ?
                            ann.value() :
                            new Class[]{findClosestExceptionTypeFromMethodParams(bestMatchingMethod, exception.getClass())};


                    log.debug("ASEP: Found best matching handler method [{}] in bean [{}] for exception [{}] and accepted media type [{}]. Produces: {}, Priority: {}",
                            bestMatchingMethod.getName(), adviceBean.getClass().getSimpleName(),
                            exception.getClass().getSimpleName(), acceptedMediaType, Arrays.toString(produces), priority);
                    return new HandlerMethod(adviceBean, bestMatchingMethod, handledExceptions, priority, produces);
                }
            }
        }

        log.debug("ASEP: No suitable @SecurityExceptionHandler method found in any @SecurityControllerAdvice beans for exception [{}] and accepted media types {}.",
                exception.getClass().getName(), acceptedMediaTypes);
        return null;
    }

    @SuppressWarnings("unchecked")
    private Class<? extends Throwable> findClosestExceptionTypeFromMethodParams(Method method, Class<? extends Throwable> actualExceptionType) {
        for (Class<?> paramType : method.getParameterTypes()) {
            if (Throwable.class.isAssignableFrom(paramType) && paramType.isAssignableFrom(actualExceptionType)) {
                return (Class<? extends Throwable>) paramType;
            }
        }
        // 파라미터에서 못찾으면, 메소드가 처리하기로 한 예외 중 가장 가까운 것을 찾거나, Throwable.class 반환
        // (ExceptionHandlerMethodResolver가 이미 예외 계층을 고려하므로, 여기서는 간단히 Throwable.class)
        return Throwable.class;
    }


    /**
     * Spring MVC의 ExceptionHandlerMethodResolver와 유사한 기능을 수행하며,
     * @SecurityExceptionHandler 어노테이션을 처리합니다.
     */
    private static class ExceptionHandlerMethodResolver {
        private static final MethodFilter EXCEPTION_HANDLER_METHODS = method ->
                AnnotatedElementUtils.hasAnnotation(method, SecurityExceptionHandler.class);

        // Key: 예외 타입, Value: 해당 예외 타입을 처리하는 메소드들 (우선순위 + produces 고려 필요)
        // 여기서는 간단히 <예외타입, 메소드> 로 하고, Content Negotiation은 외부에서 수행
        private final Map<Class<? extends Throwable>, Method> mappedMethods = new LinkedHashMap<>();
        // <메소드, ResolvedExceptionHandlerMethodInfo> 와 같은 캐시 구조도 가능
        private final Map<Method, ExceptionHandlerMappingInfo> methodMappings = new LinkedHashMap<>();


        public ExceptionHandlerMethodResolver(Class<?> handlerType) {
            for (Method method : MethodIntrospector.selectMethods(handlerType, EXCEPTION_HANDLER_METHODS)) {
                SecurityExceptionHandler ann = AnnotatedElementUtils.findMergedAnnotation(method, SecurityExceptionHandler.class);
                if (ann == null) continue; // Should not happen due to MethodFilter

                Class<? extends Throwable>[] exceptionTypes = ann.value();
                if (exceptionTypes.length == 0) {
                    exceptionTypes = detectExceptionMappingsFromMethodParams(method);
                }
                if (exceptionTypes.length == 0) {
                    // 명시도, 파라미터도 없으면 모든 예외(Throwable) 처리로 간주
                    exceptionTypes = new Class[]{Throwable.class};
                    log.warn("ASEP: No exception types mapped to @SecurityExceptionHandler method {} by annotation or parameter. " +
                            "Defaulting to handle Throwable.class with priority {}.", method.toGenericString(), ann.priority());
                }

                ExceptionHandlerMappingInfo mappingInfo = new ExceptionHandlerMappingInfo(
                        Set.of(exceptionTypes), // 중복 제거 및 불변 Set
                        parseProducesMediaTypes(ann.produces(), method),
                        method,
                        ann.priority()
                );
                this.methodMappings.put(method, mappingInfo);

                for (Class<? extends Throwable> exceptionType : exceptionTypes) {
                    Method oldMethod = this.mappedMethods.get(exceptionType);
                    if (oldMethod != null && !oldMethod.equals(method)) {
                        // TODO: 우선순위 등을 고려한 충돌 해결 로직 필요
                        // 현재는 마지막에 발견된 것으로 덮어쓰거나, 예외 발생 가능
                        // Spring MVC는 더 정교한 충돌 감지 및 우선순위 비교 로직 가짐
                        log.warn("ASEP: Ambiguous @SecurityExceptionHandler method mapped for [{}]: Old=[{}], New=[{}]. New one will be used if not resolved by priority/produces.",
                                exceptionType.getName(), oldMethod.getName(), method.getName());
                    }
                    // TODO: 우선순위와 produces를 고려하여 가장 적합한 메소드를 mappedMethods에 저장해야 함.
                    // 여기서는 단순히 첫번째/마지막 발견된 메소드를 저장하는 대신, ExceptionHandlerMappingInfo를 저장하고,
                    // resolveMethod에서 이 정보를 활용하여 최적의 메소드를 찾아야 함.
                    // 지금은 간단히 첫번째/마지막 메소드를 저장한다고 가정 (개선 필요 지점)
                    this.mappedMethods.put(exceptionType, method);
                }
            }
        }

        private Set<MediaType> parseProducesMediaTypes(String[] produces, Method method) {
            if (produces == null || produces.length == 0) {
                return Collections.emptySet(); // 명시적 produces 없으면 모든 타입 수용
            }
            Set<MediaType> mediaTypes = new LinkedHashSet<>();
            for (String mediaTypeStr : produces) {
                try {
                    mediaTypes.add(MediaType.parseMediaType(mediaTypeStr));
                } catch (Exception e) {
                    log.warn("ASEP: Invalid media type '{}' declared on @SecurityExceptionHandler for method {}. It will be ignored.",
                            mediaTypeStr, method.toGenericString(), e);
                }
            }
            return Collections.unmodifiableSet(mediaTypes);
        }


        @SuppressWarnings("unchecked")
        private Class<? extends Throwable>[] detectExceptionMappingsFromMethodParams(Method method) {
            List<Class<? extends Throwable>> types = new ArrayList<>();
            for (Class<?> paramType : method.getParameterTypes()) {
                if (Throwable.class.isAssignableFrom(paramType)) {
                    types.add((Class<? extends Throwable>) paramType);
                }
            }
            return types.toArray(new Class[0]);
        }

        public boolean hasExceptionMappings() {
            return !this.methodMappings.isEmpty();
        }

        @Nullable
        public Method resolveMethod(Throwable exception, MediaType acceptedMediaType) {
            Class<? extends Throwable> exceptionType = exception.getClass();
            List<ExceptionHandlerMappingInfo> C = new ArrayList<>();

            // 1. 정확히 일치하거나 부모 타입인 예외를 처리하는 모든 메소드 후보 수집
            for (ExceptionHandlerMappingInfo mappingInfo : this.methodMappings.values()) {
                for (Class<? extends Throwable> mappedExType : mappingInfo.exceptionTypes()) {
                    if (mappedExType.isAssignableFrom(exceptionType)) {
                        C.add(mappingInfo);
                        break;
                    }
                }
            }

            if (C.isEmpty()) {
                // cause 확인
                Throwable cause = exception.getCause();
                if (cause != null) {
                    return resolveMethod(cause, acceptedMediaType);
                }
                return null;
            }

            // 2. 후보들을 예외 깊이 -> 우선순위 순으로 정렬
            C.sort(new ExceptionHandlerMappingInfoComparator(exceptionType));

            // 3. 정렬된 후보들 중에서 Content Negotiation (produces vs acceptedMediaType)을 만족하는 첫 번째 메소드 반환
            for (ExceptionHandlerMappingInfo mappingInfo : C) {
                if (mappingInfo.matches(acceptedMediaType)) {
                    return mappingInfo.handlerMethod();
                }
            }

            // 4. Content Negotiation 만족하는 것이 없으면, produces 없는 핸들러 또는 우선순위 가장 높은 것 반환 (정책에 따라)
            // 여기서는 가장 우선순위 높은 (정렬된 리스트의 첫번째) 메소드가 produces가 없거나 MediaType.ALL을 포함하면 그것을 반환
            if (!C.isEmpty()) {
                ExceptionHandlerMappingInfo bestOverall = C.get(0);
                if (bestOverall.producibleMediaTypes().isEmpty() ||
                        bestOverall.producibleMediaTypes().stream().anyMatch(mt -> mt.isCompatibleWith(MediaType.ALL))) {
                    return bestOverall.handlerMethod();
                }
            }

            return null; // 적합한 메소드 없음
        }

        /**
         * Spring MVC의 ExceptionHandlerMethodResolver.resolveMethodByExceptionType 과 유사하게,
         * 가장 구체적인 예외 타입을 처리하는 메소드를 찾습니다. (Content Negotiation 미적용)
         */
        @Nullable
        public Method resolveMethodByExceptionType(Class<? extends Throwable> exceptionType) {
            List<ExceptionHandlerMappingInfo> C = new ArrayList<>();
            for (ExceptionHandlerMappingInfo mappingInfo : this.methodMappings.values()) {
                for (Class<? extends Throwable> mappedExType : mappingInfo.exceptionTypes()) {
                    if (mappedExType.isAssignableFrom(exceptionType)) {
                        C.add(mappingInfo);
                        break;
                    }
                }
            }
            if (C.isEmpty()) return null;
            C.sort(new ExceptionHandlerMappingInfoComparator(exceptionType));
            return C.get(0).handlerMethod();
        }


        // 레코드(Java 16+) 또는 간단한 클래스로 ExceptionHandlerMappingInfo 정의
        private record ExceptionHandlerMappingInfo(
                Set<Class<? extends Throwable>> exceptionTypes,
                Set<MediaType> producibleMediaTypes,
                Method handlerMethod,
                int priority
        ) {
            public boolean matches(MediaType acceptedMediaType) {
                if (this.producibleMediaTypes.isEmpty()) {
                    return true; // produces 명시 안하면 모든 타입 수용
                }
                for (MediaType producible : this.producibleMediaTypes) {
                    if (acceptedMediaType.isCompatibleWith(producible)) {
                        return true;
                    }
                }
                return false;
            }
        }

        private static class ExceptionHandlerMappingInfoComparator implements Comparator<ExceptionHandlerMappingInfo> {
            private final Class<? extends Throwable> exceptionType;

            public ExceptionHandlerMappingInfoComparator(Class<? extends Throwable> exceptionType) {
                this.exceptionType = exceptionType;
            }

            @Override
            public int compare(ExceptionHandlerMappingInfo o1, ExceptionHandlerMappingInfo o2) {
                // 1. 예외 깊이 비교 (더 구체적인 예외 타입 우선)
                int depth1 = getDepth(o1);
                int depth2 = getDepth(o2);
                if (depth1 != depth2) {
                    return Integer.compare(depth1, depth2);
                }
                // 2. 우선순위 비교 (낮은 값 = 높은 우선순위)
                return Integer.compare(o1.priority(), o2.priority());
            }

            private int getDepth(ExceptionHandlerMappingInfo mappingInfo) {
                // 이 매핑이 현재 발생한 exceptionType을 처리할 수 있는 가장 가까운 깊이
                return mappingInfo.exceptionTypes().stream()
                        .filter(type -> type.isAssignableFrom(this.exceptionType))
                        .mapToInt(type -> calculateDepth(type, this.exceptionType, 0))
                        .min()
                        .orElse(Integer.MAX_VALUE);
            }

            private int calculateDepth(Class<?> mappedType, Class<?> targetType, int depth) {
                if (targetType == null || targetType.equals(Object.class)) { // Throwable 보다 더 올라가지 않도록
                    return Integer.MAX_VALUE;
                }
                if (mappedType.equals(targetType)) {
                    return depth;
                }
                return calculateDepth(mappedType, targetType.getSuperclass(), depth + 1);
            }
        }
    }
}
