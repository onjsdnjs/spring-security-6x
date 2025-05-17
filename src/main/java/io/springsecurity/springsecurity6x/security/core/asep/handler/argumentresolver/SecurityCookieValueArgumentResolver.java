package io.springsecurity.springsecurity6x.security.core.asep.handler.argumentresolver;

import io.springsecurity.springsecurity6x.security.core.asep.annotation.SecurityCookieValue;
import io.springsecurity.springsecurity6x.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.MethodParameter;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ValueConstants;

public class SecurityCookieValueArgumentResolver implements SecurityHandlerMethodArgumentResolver {

    private final ConversionService conversionService;

    public SecurityCookieValueArgumentResolver(ConversionService conversionService) {
        Assert.notNull(conversionService, "ConversionService must not be null");
        this.conversionService = conversionService;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(SecurityCookieValue.class);
    }

    @Override
    @Nullable
    public Object resolveArgument(MethodParameter parameter,
                                  HttpServletRequest request,
                                  HttpServletResponse response,
                                  @Nullable Authentication authentication,
                                  @Nullable Throwable caughtException,
                                  HandlerMethod handlerMethod) throws Exception {

        SecurityCookieValue annotation = parameter.getParameterAnnotation(SecurityCookieValue.class);
        if (annotation == null) { return null; }

        String cookieName = annotation.name();
        if (!StringUtils.hasText(cookieName)) {
            cookieName = parameter.getParameterName();
            if (cookieName == null) {
                throw new IllegalArgumentException("Cookie name for argument type [" + parameter.getParameterType().getName() +
                        "] not specified, and parameter name information not available.");
            }
        }

        Cookie foundCookie = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    foundCookie = cookie;
                    break;
                }
            }
        }

        if (Cookie.class.isAssignableFrom(parameter.getParameterType())) {
            if (foundCookie == null && annotation.required()) {
                throw new MissingCookieException(cookieName, parameter);
            }
            return foundCookie;
        }

        Object resolvedValue = null;
        if (foundCookie == null) {
            if (annotation.required()) {
                throw new MissingCookieException(cookieName, parameter);
            }
            String defaultValue = annotation.defaultValue();
            if (!ValueConstants.DEFAULT_NONE.equals(defaultValue)) {
                resolvedValue = convertValue(defaultValue, parameter);
            }
        } else {
            resolvedValue = convertValue(foundCookie.getValue(), parameter);
        }
        return resolvedValue;
    }

    private Object convertValue(@Nullable String value, MethodParameter parameter) {
        if (value == null) { return null; }
        TypeDescriptor sourceType = TypeDescriptor.valueOf(String.class);
        TypeDescriptor targetType = new TypeDescriptor(parameter);

        if (this.conversionService.canConvert(sourceType, targetType)) {
            return this.conversionService.convert(value, sourceType, targetType);
        } else if (String.class.isAssignableFrom(parameter.getParameterType()) && parameter.getParameterType().isInstance(value)) {
            return value;
        }
        throw new IllegalStateException("Cannot convert String [" + value + "] to target type [" +
                parameter.getParameterType().getName() + "] for parameter [" + parameter.getParameterName() + "]");
    }

    public static class MissingCookieException extends RuntimeException {
        private final String cookieName;
        private final MethodParameter parameter;
        public MissingCookieException(String cookieName, MethodParameter parameter) {
            super("Required cookie '" + cookieName + "' for method parameter type " +
                    parameter.getParameterType().getName() + " is not present");
            this.cookieName = cookieName;
            this.parameter = parameter;
        }
        public String getCookieName() { return this.cookieName; }
        public MethodParameter getMethodParameter() { return this.parameter; }
    }
}
