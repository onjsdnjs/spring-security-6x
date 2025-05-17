package io.springsecurity.springsecurity6x.security.core.asep.handler.argumentresolver;

import io.springsecurity.springsecurity6x.security.core.asep.annotation.SecuritySessionAttribute;
import io.springsecurity.springsecurity6x.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.core.MethodParameter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

public class SecuritySessionAttributeArgumentResolver implements SecurityHandlerMethodArgumentResolver {

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(SecuritySessionAttribute.class);
    }

    @Override
    @Nullable
    public Object resolveArgument(MethodParameter parameter,
                                  HttpServletRequest request,
                                  HttpServletResponse response,
                                  @Nullable Authentication authentication,
                                  @Nullable Throwable caughtException,
                                  HandlerMethod handlerMethod) throws Exception {

        SecuritySessionAttribute annotation = parameter.getParameterAnnotation(SecuritySessionAttribute.class);
        if (annotation == null) { return null; }

        HttpSession session = request.getSession(false);
        if (session == null && annotation.required()) {
            throw new MissingSessionAttributeException(annotation.name(), parameter, "No HttpSession found");
        } else if (session == null) {
            return null;
        }

        String attributeName = annotation.name();
        if (!StringUtils.hasText(attributeName)) {
            attributeName = parameter.getParameterName();
            if (attributeName == null) {
                throw new IllegalArgumentException("Session attribute name for argument type [" + parameter.getParameterType().getName() +
                        "] not specified, and parameter name information not available.");
            }
        }

        Object attributeValue = session.getAttribute(attributeName);

        if (attributeValue == null) {
            if (annotation.required()) {
                throw new MissingSessionAttributeException(attributeName, parameter, "Attribute not found in session");
            }
            return null;
        }

        if (parameter.getParameterType().isInstance(attributeValue)) {
            return attributeValue;
        }
        throw new IllegalArgumentException("Session attribute '" + attributeName + "' is of type [" + attributeValue.getClass().getName() +
                "] but method parameter type is [" + parameter.getParameterType().getName() + "]");
    }

    public static class MissingSessionAttributeException extends RuntimeException {
        private final String attributeName;
        private final MethodParameter parameter;
        public MissingSessionAttributeException(String attributeName, MethodParameter parameter, String reason) {
            super("Required session attribute '" + attributeName + "' for method parameter type " +
                    parameter.getParameterType().getName() + " is not present: " + reason);
            this.attributeName = attributeName;
            this.parameter = parameter;
        }
        public String getAttributeName() { return this.attributeName; }
        public MethodParameter getMethodParameter() { return this.parameter; }
    }
}
