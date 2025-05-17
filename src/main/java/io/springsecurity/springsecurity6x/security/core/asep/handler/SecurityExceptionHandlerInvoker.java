package io.springsecurity.springsecurity6x.security.core.asep.handler;

import io.springsecurity.springsecurity6x.security.core.asep.handler.argumentresolver.SecurityHandlerMethodArgumentResolver;
import io.springsecurity.springsecurity6x.security.core.asep.handler.model.HandlerMethod;
import io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler.SecurityHandlerMethodReturnValueHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.MethodParameter;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.core.annotation.AnnotationAwareOrderComparator; // 정렬용
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class SecurityExceptionHandlerInvoker {

    private static final Logger logger = LoggerFactory.getLogger(SecurityExceptionHandlerInvoker.class);

    private final List<SecurityHandlerMethodArgumentResolver> argumentResolvers;
    private final List<SecurityHandlerMethodReturnValueHandler> returnValueHandlers;
    private final ParameterNameDiscoverer parameterNameDiscoverer = new DefaultParameterNameDiscoverer();

    public SecurityExceptionHandlerInvoker(List<SecurityHandlerMethodArgumentResolver> argumentResolvers,
                                           List<SecurityHandlerMethodReturnValueHandler> returnValueHandlers) {
        this.argumentResolvers = (argumentResolvers != null) ? new ArrayList<>(argumentResolvers) : Collections.emptyList();
        this.returnValueHandlers = (returnValueHandlers != null) ? new ArrayList<>(returnValueHandlers) : Collections.emptyList();

        // 주입된 Resolver와 Handler를 우선순위에 따라 정렬
        AnnotationAwareOrderComparator.sort(this.argumentResolvers);
        AnnotationAwareOrderComparator.sort(this.returnValueHandlers);
    }

    public void invokeHandlerMethod(HttpServletRequest request,
                                    HttpServletResponse response,
                                    Authentication authentication,
                                    Throwable exception,
                                    HandlerMethod handlerMethod,
                                    MediaType resolvedMediaType) throws Exception {
        Assert.notNull(handlerMethod, "HandlerMethod cannot be null");
        Method methodToInvoke = handlerMethod.getMethod();

        Object[] args = getMethodArgumentValues(request, response, authentication, exception, handlerMethod);

        Object returnValue;
        try {
            if (logger.isDebugEnabled()) {
                logger.debug("Invoking @SecurityExceptionHandler method: {}", methodToInvoke.toGenericString());
            }
            returnValue = methodToInvoke.invoke(handlerMethod.getBean(), args);
        } catch (InvocationTargetException ex) {
            Throwable targetException = ex.getTargetException();
            logger.warn("Exception thrown from @SecurityExceptionHandler method [{}]: {}",
                    methodToInvoke.getName(), targetException.getMessage(), targetException);
            if (targetException instanceof Error) {
                throw (Error) targetException;
            }
            throw (Exception) targetException;
        }

        MethodParameter returnType = new MethodParameter(methodToInvoke, -1);
        handleReturnValue(returnValue, returnType, request, response, authentication, handlerMethod, resolvedMediaType);
    }

    private Object[] getMethodArgumentValues(HttpServletRequest request,
                                             HttpServletResponse response,
                                             Authentication authentication,
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

            SecurityHandlerMethodArgumentResolver selectedResolver = null;
            for (SecurityHandlerMethodArgumentResolver resolver : this.argumentResolvers) {
                if (resolver.supportsParameter(parameter)) {
                    selectedResolver = resolver;
                    break;
                }
            }

            if (selectedResolver == null) {
                throw new IllegalStateException("No suitable SecurityHandlerMethodArgumentResolver found for parameter type [" +
                        parameter.getParameterType().getName() + "] in method [" + method.getName() + "]");
            }
            args[i] = selectedResolver.resolveArgument(parameter, request, response, authentication, caughtException, handlerMethod);
        }
        return args;
    }

    private void handleReturnValue(Object returnValue,
                                   MethodParameter returnType,
                                   HttpServletRequest request,
                                   HttpServletResponse response,
                                   Authentication authentication,
                                   HandlerMethod handlerMethod,
                                   MediaType resolvedMediaType) throws Exception {
        SecurityHandlerMethodReturnValueHandler selectedHandler = null;
        for (SecurityHandlerMethodReturnValueHandler handler : this.returnValueHandlers) {
            if (handler.supportsReturnType(returnType)) {
                selectedHandler = handler;
                break;
            }
        }

        if (selectedHandler == null) {
            if (returnValue == null && returnType.getParameterType().equals(void.class)) {
                logger.debug("Handler method [{}] returned void, no specific return value handler needed.", handlerMethod.getMethod().getName());
                return;
            }
            throw new IllegalStateException("No suitable SecurityHandlerMethodReturnValueHandler found for return type [" +
                    returnType.getParameterType().getName() + "] from method [" + handlerMethod.getMethod().getName() + "]");
        }
        selectedHandler.handleReturnValue(returnValue, returnType, request, response, authentication, handlerMethod, resolvedMediaType);
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
