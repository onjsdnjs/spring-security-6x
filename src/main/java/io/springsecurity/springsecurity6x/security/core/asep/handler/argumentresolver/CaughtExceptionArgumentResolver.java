package io.springsecurity.springsecurity6x.security.core.asep.handler.argumentresolver;

import io.springsecurity.springsecurity6x.security.core.asep.annotation.CaughtException;
import io.springsecurity.springsecurity6x.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

@Slf4j
public class CaughtExceptionArgumentResolver implements SecurityHandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(CaughtException.class) &&
                Throwable.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    @Nullable
    public Object resolveArgument(MethodParameter parameter,
                                  HttpServletRequest request,
                                  HttpServletResponse response,
                                  @Nullable Authentication authentication,
                                  @Nullable Throwable caughtException,
                                  HandlerMethod handlerMethod) throws Exception {
        Assert.notNull(caughtException, "CaughtException cannot be null when resolving @CaughtException");

        if (parameter.getParameterType().isAssignableFrom(caughtException.getClass())) {
            return caughtException;
        }
        // 타입이 정확히 일치하지 않아도, 할당 가능하다면 반환 (상위 타입으로 받을 경우)
        if (parameter.getParameterType().isInstance(caughtException)) {
            return caughtException;
        }
        log.warn("Caught exception type [{}] is not assignable to parameter type [{}] for @CaughtException.",
                caughtException.getClass().getName(), parameter.getParameterType().getName());
        return null; // 또는 예외 발생
    }
}
