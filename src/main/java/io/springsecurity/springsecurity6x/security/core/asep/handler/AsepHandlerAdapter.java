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
import java.util.ArrayList;
import java.util.List;

/**
 * ASEP의 예외 핸들러 메소드를 실행하고,
 * ArgumentResolver 및 ReturnValueHandler를 사용하여 인자 준비 및 반환 값 처리를 수행합니다.
 * 이 클래스는 POJO로 설계되어 각 SecurityFilterChain 스코프별로 인스턴스화될 수 있습니다.
 */
@Slf4j
public class AsepHandlerAdapter {


    private final List<SecurityHandlerMethodArgumentResolver> argumentResolvers;
    private final List<SecurityHandlerMethodReturnValueHandler> returnValueHandlers;
    private final ParameterNameDiscoverer parameterNameDiscoverer = new DefaultParameterNameDiscoverer();

    /**
     * 생성자.
     * @param argumentResolvers 이 어댑터 인스턴스가 사용할 ArgumentResolver 리스트 (커스텀 + 기본 조합 및 정렬 완료)
     * @param returnValueHandlers 이 어댑터 인스턴스가 사용할 ReturnValueHandler 리스트 (커스텀 + 기본 조합 및 정렬 완료)
     */
    public AsepHandlerAdapter(List<SecurityHandlerMethodArgumentResolver> argumentResolvers,
                              List<SecurityHandlerMethodReturnValueHandler> returnValueHandlers) {
        Assert.notNull(argumentResolvers, "ArgumentResolvers must not be null");
        Assert.notNull(returnValueHandlers, "ReturnValueHandlers must not be null");

        // 방어적 복사를 통해 외부에서의 리스트 변경 방지
        this.argumentResolvers = new ArrayList<>(argumentResolvers);
        this.returnValueHandlers = new ArrayList<>(returnValueHandlers);

        // 생성 시점에 이미 정렬된 리스트를 받는 것을 가정하거나, 여기서 한 번 더 정렬할 수 있음.
        // GlobalConfigurer 에서 최종 리스트를 만들 때 정렬하는 것이 더 효율적일 수 있음.
        // AnnotationAwareOrderComparator.sort(this.argumentResolvers);
        // AnnotationAwareOrderComparator.sort(this.returnValueHandlers);
    }

    /**
     * 주어진 HandlerMethod를 실행합니다.
     */
    public void invokeHandlerMethod(HttpServletRequest request,
                                    HttpServletResponse response,
                                    @Nullable Authentication authentication,
                                    Throwable exception,
                                    HandlerMethod handlerMethod,
                                    @Nullable MediaType resolvedMediaType) throws Exception {
        Assert.notNull(handlerMethod, "HandlerMethod cannot be null");
        Method methodToInvoke = handlerMethod.getMethod();

        Object[] args = getMethodArgumentValues(request, response, authentication, exception, handlerMethod);

        Object returnValue;
        try {
            if (log.isDebugEnabled()) {
                log.debug("Invoking ASEP exception handler method: {}", methodToInvoke.toGenericString());
            }
            returnValue = methodToInvoke.invoke(handlerMethod.getBean(), args);
        } catch (InvocationTargetException ex) {
            // 핸들러 메소드 내부에서 발생한 예외는 원인 예외를 추출하여 다시 던짐
            Throwable targetException = ex.getTargetException();
            log.warn("Exception thrown from ASEP handler method [{}]: {}",
                    methodToInvoke.getName(), targetException.getMessage(), targetException);
            if (targetException instanceof Error) {
                throw (Error) targetException;
            }
            throw (Exception) targetException;
        }

        MethodParameter returnTypeParameter = new MethodParameter(methodToInvoke, -1); // -1 for return type
        handleReturnValue(returnValue, returnTypeParameter, request, response, authentication, handlerMethod, resolvedMediaType);
    }

    private Object[] getMethodArgumentValues(HttpServletRequest request,
                                             HttpServletResponse response,
                                             @Nullable Authentication authentication,
                                             Throwable caughtException,
                                             HandlerMethod handlerMethod) throws Exception {
        Method method = handlerMethod.getMethod();
        MethodParameter[] parameters = getMethodParameters(method);
        if (parameters.length == 0) {
            return new Object[0];
        }

        Object[] args = new Object[parameters.length];
        for (int i = 0; i < parameters.length; i++) {
            MethodParameter parameter = parameters[i];
            parameter.initParameterNameDiscovery(this.parameterNameDiscoverer);

            SecurityHandlerMethodArgumentResolver selectedResolver = findSupportingResolver(parameter);
            if (selectedResolver == null) {
                throw new IllegalStateException("No suitable SecurityHandlerMethodArgumentResolver found for parameter type [" +
                        parameter.getParameterType().getName() + "] in method [" + method.getName() + "]");
            }

            try {
                args[i] = selectedResolver.resolveArgument(
                        parameter, request, response, authentication, caughtException, handlerMethod
                );
            } catch (Exception ex) {
                log.error("Error resolving argument for parameter [{}] in method [{}]: {}",
                        parameter.getParameterName(), method.getName(), ex.getMessage(), ex);
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

    private void handleReturnValue(@Nullable Object returnValue,
                                   MethodParameter returnType,
                                   HttpServletRequest request,
                                   HttpServletResponse response,
                                   @Nullable Authentication authentication,
                                   HandlerMethod handlerMethod,
                                   @Nullable MediaType resolvedMediaType) throws Exception {

        SecurityHandlerMethodReturnValueHandler selectedHandler = findSupportingReturnValueHandler(returnType);

        if (selectedHandler != null) {
            try {
                selectedHandler.handleReturnValue(
                        returnValue, returnType, request, response, authentication, handlerMethod, resolvedMediaType
                );
            } catch (Exception ex) {
                log.error("Error handling return value for method [{}]: {}",
                        handlerMethod.getMethod().getName(), ex.getMessage(), ex);
                throw ex;
            }
        } else {
            // void 반환 타입이거나, 반환 값이 null 이고 핸들러가 이를 명시적으로 처리하지 않은 경우
            if (returnValue == null && (returnType.getParameterType().equals(void.class) || returnType.getParameterType().equals(Void.class))) {
                log.debug("Handler method [{}] returned void or null, and no specific ReturnValueHandler processed it.",
                        handlerMethod.getMethod().getName());
                // 응답이 이미 커밋되지 않았다면, 기본적으로 여기서 응답이 완료된 것으로 간주할 수 있음.
                // 또는 특정 상황(예: 비동기 처리)을 위한 추가 로직이 필요할 수 있음.
                return;
            }
            // 지원하는 핸들러가 없고, void 반환도 아닌 경우
            throw new IllegalStateException("No suitable SecurityHandlerMethodReturnValueHandler found for return type [" +
                    returnType.getParameterType().getName() + "] from method [" + handlerMethod.getMethod().getName() + "]");
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
