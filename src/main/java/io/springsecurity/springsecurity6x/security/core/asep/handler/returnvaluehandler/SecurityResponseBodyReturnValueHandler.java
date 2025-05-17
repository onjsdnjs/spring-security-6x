package io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler;

import io.springsecurity.springsecurity6x.security.core.asep.annotation.SecurityResponseBody;
import io.springsecurity.springsecurity6x.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.http.HttpHeaders; // HttpHeaders 추가
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.MimeTypeUtils;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class SecurityResponseBodyReturnValueHandler implements SecurityHandlerMethodReturnValueHandler {

    private static final Logger logger = LoggerFactory.getLogger(SecurityResponseBodyReturnValueHandler.class);
    private final List<HttpMessageConverter<?>> messageConverters;

    public SecurityResponseBodyReturnValueHandler(List<HttpMessageConverter<?>> messageConverters) {
        Assert.notNull(messageConverters, "HttpMessageConverters must not be null or empty for SecurityResponseBodyReturnValueHandler");
        this.messageConverters = messageConverters.isEmpty() ? Collections.emptyList() : messageConverters;
    }

    @Override
    public boolean supportsReturnType(MethodParameter returnType) {
        return (AnnotatedElementUtils.hasAnnotation(returnType.getContainingClass(), SecurityResponseBody.class) ||
                returnType.hasMethodAnnotation(SecurityResponseBody.class));
    }

    @Override
    public void handleReturnValue(@Nullable Object returnValue,
                                  MethodParameter returnType,
                                  HttpServletRequest request,
                                  HttpServletResponse response,
                                  @Nullable Authentication authentication,
                                  HandlerMethod handlerMethod,
                                  @Nullable MediaType resolvedMediaType) throws Exception {
        if (returnValue == null) {
            logger.debug("Method [{}] with @SecurityResponseBody returned null. No body will be written.",
                    handlerMethod.getMethod().getName());
            // Consider setting SC_NO_CONTENT if appropriate and response not committed
            // if (!response.isCommitted()) { response.setStatus(HttpServletResponse.SC_NO_CONTENT); }
            return;
        }

        ServletServerHttpResponse outputMessage = new ServletServerHttpResponse(response);
        MediaType selectedMediaType = resolvedMediaType;

        if (selectedMediaType == null || selectedMediaType.isWildcardType() || selectedMediaType.isWildcardSubtype()) {
            // Fallback logic for selectedMediaType if not properly resolved
            // This might involve checking Accept header again or using a default
            String acceptHeader = request.getHeader(HttpHeaders.ACCEPT);
            if (acceptHeader != null && !acceptHeader.trim().isEmpty() && !acceptHeader.equals("*/*")) {
                List<MediaType> acceptedMediaTypes = MediaType.parseMediaTypes(acceptHeader);
                MimeTypeUtils.sortBySpecificity(acceptedMediaTypes);
                if (!acceptedMediaTypes.isEmpty()) selectedMediaType = acceptedMediaTypes.get(0);
            }
            if (selectedMediaType == null || selectedMediaType.isWildcardType() || selectedMediaType.isWildcardSubtype()) {
                selectedMediaType = MediaType.APPLICATION_JSON; // Default fallback
            }
            logger.warn("ResolvedMediaType was not specific. Using {} for @SecurityResponseBody.", selectedMediaType);
        }

        outputMessage.getHeaders().setContentType(selectedMediaType);
        Class<?> returnValueClass = returnValue.getClass();

        if (this.messageConverters.isEmpty()) {
            throw new IllegalStateException("No HttpMessageConverters configured to write response body for @SecurityResponseBody");
        }

        for (HttpMessageConverter converter : this.messageConverters) {
            if (converter.canWrite(returnValueClass, selectedMediaType)) {
                try {
                    ((HttpMessageConverter<Object>) converter).write(returnValue, selectedMediaType, outputMessage);
                    return;
                } catch (IOException ex) {
                    throw ex;
                }
            }
        }
        throw new IllegalStateException("No HttpMessageConverter for " + returnValueClass.getName() + " and content type " + selectedMediaType);
    }
}
