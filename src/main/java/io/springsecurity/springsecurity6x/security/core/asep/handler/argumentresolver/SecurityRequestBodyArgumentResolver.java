package io.springsecurity.springsecurity6x.security.core.asep.handler.argumentresolver;

import io.springsecurity.springsecurity6x.security.core.asep.annotation.SecurityRequestBody;
import io.springsecurity.springsecurity6x.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.io.IOException;
import java.lang.reflect.Type;
import java.util.Collections;
import java.util.List;

public class SecurityRequestBodyArgumentResolver implements SecurityHandlerMethodArgumentResolver {

    private static final Logger logger = LoggerFactory.getLogger(SecurityRequestBodyArgumentResolver.class);
    private final List<HttpMessageConverter<?>> messageConverters;

    public SecurityRequestBodyArgumentResolver(List<HttpMessageConverter<?>> messageConverters) {
        Assert.notNull(messageConverters, "HttpMessageConverters must not be null or empty for SecurityRequestBodyArgumentResolver");
        this.messageConverters = messageConverters.isEmpty() ? Collections.emptyList() : messageConverters;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(SecurityRequestBody.class);
    }

    @Override
    @Nullable
    public Object resolveArgument(MethodParameter parameter,
                                  HttpServletRequest request,
                                  HttpServletResponse response,
                                  @Nullable Authentication authentication,
                                  @Nullable Throwable caughtException,
                                  HandlerMethod handlerMethod) throws Exception {

        SecurityRequestBody requestBodyAnnotation = parameter.getParameterAnnotation(SecurityRequestBody.class);
        if (requestBodyAnnotation == null) { return null; }

        HttpInputMessage inputMessage = new ServletServerHttpRequest(request);
        MediaType contentType = inputMessage.getHeaders().getContentType();

        Type targetType = parameter.getGenericParameterType();
        Object body = null;
        boolean bodyRead = false;

        if (this.messageConverters.isEmpty()) {
            if (requestBodyAnnotation.required()) {
                throw new IllegalStateException("No HttpMessageConverters configured to read request body for @SecurityRequestBody");
            }
            return null;
        }

        for (HttpMessageConverter<?> converter : this.messageConverters) {
            // Use parameter.getParameterType() for canRead, targetType for read
            if (converter.canRead(parameter.getParameterType(), contentType)) {
                try {
                    body = ((HttpMessageConverter<Object>) converter).read((Class<Object>)parameter.getParameterType(), inputMessage);
                    bodyRead = true;
                    break;
                } catch (IOException ex) {
                    throw new HttpMessageNotReadableException("Could not read document: " + ex.getMessage(), ex, inputMessage);
                }
            }
        }

        if (!bodyRead && requestBodyAnnotation.required()) {
            throw new HttpMessageNotReadableException("No suitable HttpMessageConverter found to read request body for type " +
                    targetType + " and content type " + (contentType != null ? contentType : "unknown"), inputMessage);
        }

        if (body == null && requestBodyAnnotation.required()) {
            throw new RequestBodyRequiredException("Request body is required for parameter type " +
                    parameter.getParameterType().getName() + " but was null (or not readable).", parameter, inputMessage);
        }
        return body;
    }

    @SuppressWarnings("serial")
    public static class HttpMessageNotReadableException extends RuntimeException {
        private final HttpInputMessage httpInputMessage;
        public HttpMessageNotReadableException(String message, HttpInputMessage httpInputMessage) {
            super(message);
            this.httpInputMessage = httpInputMessage;
        }
        public HttpMessageNotReadableException(String message, Throwable cause, HttpInputMessage httpInputMessage) {
            super(message, cause);
            this.httpInputMessage = httpInputMessage;
        }
        public HttpInputMessage getHttpInputMessage() { return httpInputMessage; }
    }

    @SuppressWarnings("serial")
    public static class RequestBodyRequiredException extends RuntimeException {
        private final MethodParameter parameter;
        private final HttpInputMessage httpInputMessage;
        public RequestBodyRequiredException(String message, MethodParameter parameter, HttpInputMessage httpInputMessage) {
            super(message);
            this.parameter = parameter;
            this.httpInputMessage = httpInputMessage;
        }
        public MethodParameter getParameter() { return parameter; }
        public HttpInputMessage getHttpInputMessage() { return httpInputMessage; }
    }
}
