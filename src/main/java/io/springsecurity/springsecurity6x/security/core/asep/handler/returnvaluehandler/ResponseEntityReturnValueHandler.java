package io.springsecurity.springsecurity6x.security.core.asep.handler.returnvaluehandler;

import io.springsecurity.springsecurity6x.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.MimeTypeUtils;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class ResponseEntityReturnValueHandler implements SecurityHandlerMethodReturnValueHandler {

    private static final Logger logger = LoggerFactory.getLogger(ResponseEntityReturnValueHandler.class);
    private final List<HttpMessageConverter<?>> messageConverters;

    public ResponseEntityReturnValueHandler(List<HttpMessageConverter<?>> messageConverters) {
        Assert.notNull(messageConverters, "HttpMessageConverters must not be null or empty for ResponseEntityReturnValueHandler");
        this.messageConverters = messageConverters.isEmpty() ? Collections.emptyList() : messageConverters;
    }

    @Override
    public boolean supportsReturnType(MethodParameter returnType) {
        return HttpEntity.class.isAssignableFrom(returnType.getParameterType());
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
            if (!response.isCommitted()) {
                // SC_OK or SC_NO_CONTENT depending on context, default behavior of Spring MVC is usually SC_OK.
                // For null ResponseEntity, it's often better to ensure status is set or handler explicitly returns no-content.
                // response.setStatus(HttpServletResponse.SC_OK);
            }
            return;
        }

        Assert.isInstanceOf(HttpEntity.class, returnValue, "HttpEntity expected");
        HttpEntity<?> responseEntity = (HttpEntity<?>) returnValue;
        ServletServerHttpResponse outputMessage = new ServletServerHttpResponse(response);

        if (responseEntity instanceof ResponseEntity) {
            response.setStatus(((ResponseEntity<?>) responseEntity).getStatusCode().value());
        }

        HttpHeaders entityHeaders = responseEntity.getHeaders();
        if (!entityHeaders.isEmpty()) {
            outputMessage.getHeaders().putAll(entityHeaders);
        }

        Object body = responseEntity.getBody();
        if (body == null) {
            outputMessage.getBody(); // Ensure headers are flushed
            return;
        }

        Class<?> bodyType = body.getClass();
        MediaType selectedMediaType = null;

        if (entityHeaders.getContentType() != null) {
            selectedMediaType = entityHeaders.getContentType();
        } else if (resolvedMediaType != null && !resolvedMediaType.isWildcardType() && !resolvedMediaType.isWildcardSubtype()) {
            selectedMediaType = resolvedMediaType;
        } else {
            String acceptHeader = request.getHeader(HttpHeaders.ACCEPT);
            if (acceptHeader != null && !acceptHeader.trim().isEmpty() && !acceptHeader.equals("*/*")) {
                List<MediaType> acceptedMediaTypes = MediaType.parseMediaTypes(acceptHeader);
                MimeTypeUtils.sortBySpecificity(acceptedMediaTypes);
                if (!acceptedMediaTypes.isEmpty()) selectedMediaType = acceptedMediaTypes.get(0);
            }
            if (selectedMediaType == null || selectedMediaType.isWildcardType() || selectedMediaType.isWildcardSubtype()) {
                selectedMediaType = MediaType.APPLICATION_JSON; // Default fallback
            }
        }

        outputMessage.getHeaders().setContentType(selectedMediaType);


        if (this.messageConverters.isEmpty()) {
            throw new IllegalStateException("No HttpMessageConverters configured to write ResponseEntity body");
        }

        for (HttpMessageConverter converter : this.messageConverters) {
            if (converter.canWrite(bodyType, selectedMediaType)) {
                try {
                    ((HttpMessageConverter<Object>) converter).write(body, selectedMediaType, outputMessage);
                    outputMessage.getBody(); // Ensure headers are flushed
                    return;
                } catch (IOException ex) {
                    throw ex;
                }
            }
        }
        throw new IllegalStateException("No HttpMessageConverter for ResponseEntity body type " + bodyType.getName() + " and content type " + selectedMediaType);
    }
}
