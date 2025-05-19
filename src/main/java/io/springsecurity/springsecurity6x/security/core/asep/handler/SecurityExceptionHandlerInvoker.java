package io.springsecurity.springsecurity6x.security.core.asep.handler;

import io.springsecurity.springsecurity6x.security.core.asep.handler.argumentresolver.SecurityHandlerMethodArgumentResolver;
import io.springsecurity.springsecurity6x.security.core.asep.handler.model.HandlerMethod;
import io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.MethodParameter;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.http.MediaType;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Objects;

/**
 * ASEP의 예외 핸들러 메소드를 실행하고,
 * ArgumentResolver 및 ReturnValueHandler를 사용하여 인자 준비 및 반환 값 처리를 수행합니다.
 * 이 클래스는 POJO로 설계되어 각 SecurityFilterChain 스코프별로 인스턴스화될 수 있습니다.
 * 기존 SecurityExceptionHandlerInvoker의 역할을 대체합니다.
 */
@Slf4j
public final class SecurityExceptionHandlerInvoker { // final class로 변경

    private final List<SecurityHandlerMethodArgumentResolver> argumentResolvers;
    private final List<SecurityHandlerMethodReturnValueHandler> returnValueHandlers;
    private final ParameterNameDiscoverer parameterNameDiscoverer = new DefaultParameterNameDiscoverer();

    /**
     * 생성자.
     * @param argumentResolvers 이 어댑터 인스턴스가 사용할 ArgumentResolver 리스트 (외부에서 정렬 완료된 리스트 권장)
     * @param returnValueHandlers 이 어댑터 인스턴스가 사용할 ReturnValueHandler 리스트 (외부에서 정렬 완료된 리스트 권장)
     */
    public SecurityExceptionHandlerInvoker(
            List<SecurityHandlerMethodArgumentResolver> argumentResolvers,
            List<SecurityHandlerMethodReturnValueHandler> returnValueHandlers) {
        Assert.notNull(argumentResolvers, "ArgumentResolvers must not be null");
        Assert.notNull(returnValueHandlers, "ReturnValueHandlers must not be null");

        // 방어적 복사를 통해 외부에서의 리스트 변경 방지 및 불변성 확보
        this.argumentResolvers = List.copyOf(argumentResolvers);
        this.returnValueHandlers = List.copyOf(returnValueHandlers);

        // 주입 시점에 정렬이 완료되었다고 가정. 필요시 여기서도 정렬 가능.
        // AnnotationAwareOrderComparator.sort(this.argumentResolvers);
        // AnnotationAwareOrderComparator.sort(this.returnValueHandlers);

        log.debug("ASEP: AsepHandlerAdapter (POJO) initialized. ArgumentResolvers: {}, ReturnValueHandlers: {}",
                this.argumentResolvers.size(), this.returnValueHandlers.size());
    }

    /**
     * 주어진 HandlerMethod를 실행합니다.
     *
     * @param request 현재 HttpServletRequest
     * @param response 현재 HttpServletResponse
     * @param authentication 현재 Authentication 객체 (nullable)
     * @param exception 발생한 예외 (nullable - 핸들러 실행 시점에는 원본 예외가 아닐 수 있으므로 nullable)
     * @param handlerMethod 실행할 HandlerMethod (non-null)
     * @param resolvedMediaType Content Negotiation을 통해 결정된 응답 미디어 타입 (nullable)
     * @throws Exception 핸들러 메소드 실행 또는 결과 처리 중 발생하는 모든 예외
     */
    public void invokeHandlerMethod(
            HttpServletRequest request,
            HttpServletResponse response,
            @Nullable Authentication authentication,
            Throwable exception, // @CaughtException 등으로 주입될 원본 예외
            HandlerMethod handlerMethod,
            @Nullable MediaType resolvedMediaType) throws Exception {

        Objects.requireNonNull(handlerMethod, "HandlerMethod cannot be null for invocation");
        Method methodToInvoke = handlerMethod.getMethod();
        Object beanToInvoke = handlerMethod.getBean();
        Objects.requireNonNull(methodToInvoke, "Method in HandlerMethod cannot be null");
        Objects.requireNonNull(beanToInvoke, "Bean in HandlerMethod cannot be null");


        Object[] args = getMethodArgumentValues(request, response, authentication, exception, handlerMethod);

        Object returnValue;
        if (log.isDebugEnabled()) {
            log.debug("ASEP: Invoking exception handler method: {} on bean: {}",
                    methodToInvoke.toGenericString(), beanToInvoke.getClass().getName());
        }
        try {
            // 접근성 확보 (private 메소드 등은 호출 불가, public 이어야 함)
            // methodToInvoke.setAccessible(true); // 필요시, 단 public 메소드 권장
            returnValue = methodToInvoke.invoke(beanToInvoke, args);
        } catch (InvocationTargetException ex) {
            // 핸들러 메소드 내부에서 발생한 예외는 원인 예외를 추출하여 다시 던짐
            Throwable targetException = ex.getTargetException();
            log.warn("ASEP: Exception thrown from handler method [{}] during ASEP processing: {}",
                    methodToInvoke.getName(), targetException.getMessage(), targetException);
            if (targetException instanceof Error error) throw error; // Error는 그대로 전파
            if (targetException instanceof Exception e) throw e;   // Exception도 그대로 전파
            // targetException이 Error나 Exception이 아닌 Throwable인 경우는 거의 없으나, 안전하게 처리
            throw new IllegalStateException("Unexpected ASEP handler method invocation target exception type: " +
                    targetException.getClass().getName(), targetException);
        } catch (IllegalAccessException ex) {
            log.error("ASEP: Could not access handler method [{}] for ASEP processing. Ensure it is public.",
                    methodToInvoke.getName(), ex);
            throw new IllegalStateException("Could not access ASEP handler method: " + ex.getMessage(), ex);
        }


        MethodParameter returnTypeParameter = new MethodParameter(methodToInvoke, -1); // -1 for return type
        handleReturnValue(returnValue, returnTypeParameter, request, response, authentication, handlerMethod, resolvedMediaType);
    }

    private Object[] getMethodArgumentValues(
            HttpServletRequest request,
            HttpServletResponse response,
            @Nullable Authentication authentication,
            Throwable caughtException, // @CaughtException 등으로 주입될 원본 예외
            HandlerMethod handlerMethod) throws Exception {

        Method method = handlerMethod.getMethod();
        MethodParameter[] parameters = getMethodParameters(method);
        if (parameters.length == 0) {
            return new Object[0]; // 인자가 없는 메소드
        }

        Object[] args = new Object[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            MethodParameter parameter = parameters[i];
            parameter.initParameterNameDiscovery(this.parameterNameDiscoverer); // 파라미터 이름 발견 활성화

            SecurityHandlerMethodArgumentResolver selectedResolver = findSupportingResolver(parameter);
            if (selectedResolver == null) {
                throw new IllegalStateException(
                        String.format("ASEP: No suitable SecurityHandlerMethodArgumentResolver found for parameter type [%s] at index %d in method [%s]",
                                parameter.getParameterType().getName(), i, method.toGenericString()));
            }

            if (log.isTraceEnabled()) {
                log.trace("ASEP: Resolving argument for parameter [{}] (type: {}) with resolver [{}] in method [{}]",
                        parameter.getParameterName(), parameter.getParameterType().getSimpleName(),
                        selectedResolver.getClass().getSimpleName(), method.getName());
            }
            try {
                args[i] = selectedResolver.resolveArgument(
                        parameter, request, response, authentication, caughtException, handlerMethod
                );
            } catch (Exception ex) {
                // ArgumentResolver 내부에서 발생한 예외는 그대로 전파하여 ASEPFilter의 바깥쪽 try-catch에서 처리
                log.error("ASEP: Error resolving argument for parameter [{}] in method [{}] using resolver [{}]: {}",
                        parameter.getParameterName(), method.getName(), selectedResolver.getClass().getSimpleName(), ex.getMessage(), ex);
                throw ex;
            }
        }
        return args;
    }

    @Nullable
    private SecurityHandlerMethodArgumentResolver findSupportingResolver(MethodParameter parameter) {
        for (SecurityHandlerMethodArgumentResolver resolver : this.argumentResolvers) {
            if (resolver.supportsParameter(parameter)) {
                return resolver;
            }
        }
        return null;
    }

    private void handleReturnValue(
            @Nullable Object returnValue,
            MethodParameter returnType, // MethodParameter로 returnType을 정확히 표현
            HttpServletRequest request,
            HttpServletResponse response,
            @Nullable Authentication authentication,
            HandlerMethod handlerMethod,
            @Nullable MediaType resolvedMediaType) throws Exception {

        SecurityHandlerMethodReturnValueHandler selectedHandler = findSupportingReturnValueHandler(returnType);

        if (selectedHandler != null) {
            if (log.isTraceEnabled()) {
                log.trace("ASEP: Handling return value of type [{}] with handler [{}] for method [{}]",
                        (returnValue != null ? returnValue.getClass().getSimpleName() : "null"),
                        selectedHandler.getClass().getSimpleName(), handlerMethod.getMethod().getName());
            }
            try {
                selectedHandler.handleReturnValue(
                        returnValue, returnType, request, response, authentication, handlerMethod, resolvedMediaType
                );
            } catch (Exception ex) {
                // ReturnValueHandler 내부에서 발생한 예외는 그대로 전파
                log.error("ASEP: Error handling return value for method [{}] using handler [{}]: {}",
                        handlerMethod.getMethod().getName(), selectedHandler.getClass().getSimpleName(), ex.getMessage(), ex);
                throw ex;
            }
        } else {
            // void 반환 타입이거나, 반환 값이 null이고 이를 처리할 명시적인 핸들러가 없는 경우
            Class<?> paramType = returnType.getParameterType();
            if (returnValue == null && (paramType.equals(void.class) || paramType.equals(Void.class))) {
                if (log.isDebugEnabled()) {
                    log.debug("ASEP: Handler method [{}] returned void or null, and no specific ReturnValueHandler processed it. " +
                                    "Assuming response was handled directly within the handler method or no content is intended.",
                            handlerMethod.getMethod().getName());
                }
                // 응답이 이미 커밋되지 않았다면, 기본적으로 여기서 응답이 완료된 것으로 간주.
                // (예: 핸들러 내에서 response.getWriter().write() 등을 직접 사용한 경우)
                return;
            }
            // 지원하는 핸들러가 없고, void 반환도 아닌 경우
            throw new IllegalStateException(
                    String.format("ASEP: No suitable SecurityHandlerMethodReturnValueHandler found for return value type [%s] from method [%s]",
                            returnType.getParameterType().getName(), handlerMethod.getMethod().toGenericString()));
        }
    }

    @Nullable
    private SecurityHandlerMethodReturnValueHandler findSupportingReturnValueHandler(MethodParameter returnType) {
        for (SecurityHandlerMethodReturnValueHandler handler : this.returnValueHandlers) {
            if (handler.supportsReturnType(returnType)) {
                return handler;
            }
        }
        return null;
    }

    private MethodParameter[] getMethodParameters(Method method) {
        int parameterCount = method.getParameterCount();
        MethodParameter[] parameters = new MethodParameter[parameterCount];
        for (int i = 0; i < parameterCount; i++) {
            parameters[i] = new MethodParameter(method, i);
        }
        return parameters;
    }
}
