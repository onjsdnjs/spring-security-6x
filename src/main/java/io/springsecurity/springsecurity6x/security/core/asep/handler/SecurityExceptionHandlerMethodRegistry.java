package io.springsecurity.springsecurity6x.security.core.asep.handler;

import io.springsecurity.springsecurity6x.security.core.asep.annotation.SecurityControllerAdvice;
import io.springsecurity.springsecurity6x.security.core.asep.annotation.SecurityExceptionHandler;
import io.springsecurity.springsecurity6x.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.MethodIntrospector;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.OrderUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.MimeTypeUtils;

import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class SecurityExceptionHandlerMethodRegistry implements ApplicationContextAware, InitializingBean {

    private static final Logger logger = LoggerFactory.getLogger(SecurityExceptionHandlerMethodRegistry.class);

    private ApplicationContext applicationContext;
    private final Map<Class<? extends Throwable>, List<HandlerMethod>> cachedHandlers = new ConcurrentHashMap<>(64);
    private final List<HandlerMethod> universalHandlers = new ArrayList<>(); // Throwable 처리

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(applicationContext, "ApplicationContext must be set");
        initExceptionHandlerMethods();
    }

    protected void initExceptionHandlerMethods() {
        List<Object> adviceBeans = new ArrayList<>(
                applicationContext.getBeansWithAnnotation(SecurityControllerAdvice.class).values()
        );
        adviceBeans.sort(Comparator.comparing(
                bean -> OrderUtils.getOrder(bean.getClass(), Ordered.LOWEST_PRECEDENCE)
        ));

        for (Object adviceBean : adviceBeans) {
            Class<?> adviceBeanType = ClassUtils.getUserClass(adviceBean);
            // TODO: @SecurityControllerAdvice의 assignableTypes, basePackages 필터링 로직 추가

            Map<Method, SecurityExceptionHandler> annotatedMethods = MethodIntrospector.selectMethods(adviceBeanType,
                    (MethodIntrospector.MetadataLookup<SecurityExceptionHandler>) method ->
                            // 이 콜백은 각 메소드에 대해 호출되며,
                            // @SecurityExceptionHandler 어노테이션이 있으면 해당 어노테이션 객체를, 없으면 null을 반환합니다.
                            // MethodIntrospector는 null이 아닌 결과만 Map에 <Method, Annotation> 형태로 수집합니다.
                            AnnotatedElementUtils.findMergedAnnotation(method, SecurityExceptionHandler.class)
            );

            for (Map.Entry<Method, SecurityExceptionHandler> entry : annotatedMethods.entrySet()) {
                Method method = entry.getKey();
                SecurityExceptionHandler handlerAnnotation = entry.getValue(); // getValue()가 어노테이션 객체
                HandlerMethod handlerMethod = new HandlerMethod(
                        adviceBean, method, handlerAnnotation.value(),
                        handlerAnnotation.priority(), handlerAnnotation.produces()
                );
                registerHandlerMethod(handlerMethod);
            }
        }

        cachedHandlers.values().forEach(list -> list.sort(Comparator.comparingInt(HandlerMethod::getPriority)));
        universalHandlers.sort(Comparator.comparingInt(HandlerMethod::getPriority));

        if (logger.isInfoEnabled()) {
            int totalHandlers = cachedHandlers.values().stream().mapToInt(List::size).sum() + universalHandlers.size();
            logger.info("Initialized {} @SecurityExceptionHandler methods from {} @SecurityControllerAdvice beans.",
                    totalHandlers, adviceBeans.size());
        }
    }

    private void registerHandlerMethod(HandlerMethod handlerMethod) {
        for (Class<? extends Throwable> exceptionType : handlerMethod.getExceptionTypes()) {
            if (Throwable.class.equals(exceptionType)) {
                universalHandlers.add(handlerMethod);
            } else {
                this.cachedHandlers.computeIfAbsent(exceptionType, k -> new ArrayList<>()).add(handlerMethod);
            }
        }
    }

    public HandlerMethod findBestExceptionHandlerMethod(Throwable exception, Authentication authentication, HttpServletRequest request) {
        Assert.notNull(exception, "Exception must not be null");
        Class<? extends Throwable> exceptionType = exception.getClass();
        List<HandlerMethod> candidateHandlers = new ArrayList<>();

        List<HandlerMethod> exactMatchHandlers = findHandlersForExceptionType(exceptionType);
        if (exactMatchHandlers != null) {
            candidateHandlers.addAll(exactMatchHandlers);
        }

        Class<?> currentType = exceptionType.getSuperclass();
        while (currentType != null && Throwable.class.isAssignableFrom(currentType)) {
            Class<? extends Throwable> throwableSuperType = (Class<? extends Throwable>) currentType;
            List<HandlerMethod> superClassHandlers = findHandlersForExceptionType(throwableSuperType);
            if (superClassHandlers != null) {
                candidateHandlers.addAll(superClassHandlers);
            }
            currentType = currentType.getSuperclass();
        }
        candidateHandlers.addAll(this.universalHandlers);

        if (candidateHandlers.isEmpty()) {
            return null;
        }

        // 우선순위로 먼저 정렬
        candidateHandlers.sort(Comparator.comparingInt(HandlerMethod::getPriority));

        // Content Negotiation: produces와 Accept 헤더를 고려하여 최적 핸들러 선택
        // Spring MVC 의 AbstractHandlerMethodMapping 및 ProducesRequestCondition 로직 참고
        // 여기서는 ContentNegotiationManager를 사용한 간소화된 예시 (또는 직접 로직 구현)
        List<MediaType> requestedMediaTypes = getMediaTypes(request);

        for (HandlerMethod handler : candidateHandlers) {
            if (handler.getProduces().isEmpty()) { // produces가 없으면 모든 타입 수용
                return handler;
            }
            List<MediaType> producedMediaTypes = handler.getProduces().stream().map(MediaType::parseMediaType).toList();
            for (MediaType requestedType : requestedMediaTypes) {
                for (MediaType producedType : producedMediaTypes) {
                    if (requestedType.isCompatibleWith(producedType)) {
                        return handler; // 첫 번째 매칭 핸들러 반환
                    }
                }
            }
        }

        // Content Negotiation에 실패하고, produces가 명시된 핸들러만 있다면, 첫 번째 후보 반환 (또는 null 반환 정책)
        // 혹은, produces가 없는 핸들러를 우선시 할 수도 있음.
        // 여기서는 Content Negotiation 실패 시, 우선순위가 가장 높은 핸들러를 반환 (이미 정렬됨)
        return candidateHandlers.getFirst();
    }

    private List<HandlerMethod> findHandlersForExceptionType(Class<? extends Throwable> exceptionType) {
        return this.cachedHandlers.get(exceptionType); // 이미 우선순위 정렬됨
    }

    private List<MediaType> getMediaTypes(HttpServletRequest request) {
        String acceptHeader = request.getHeader(HttpHeaders.ACCEPT);
        if (acceptHeader == null || acceptHeader.trim().isEmpty()) {
            return Collections.singletonList(MediaType.ALL); // Accept 헤더 없으면 모든 타입
        }
        List<MediaType> mediaTypes = MediaType.parseMediaTypes(acceptHeader);
        MimeTypeUtils.sortBySpecificity(mediaTypes);
        return mediaTypes;
    }
}
