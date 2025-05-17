package io.springsecurity.springsecurity6x.security.core.asep.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse; // HttpMessageConverter와 함께 사용
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap; // 간단한 JSON 객체 생성을 위해
import java.util.List;
import java.util.Map; // 간단한 JSON 객체 생성을 위해

public class ASEPFilter extends OncePerRequestFilter implements Ordered {

    private static final Logger logger = LoggerFactory.getLogger(ASEPFilter.class);

    public static final int ASEP_FILTER_ORDER = Ordered.HIGHEST_PRECEDENCE + 100;

    private final SecurityExceptionHandlerMethodRegistry handlerRegistry;
    private final SecurityExceptionHandlerInvoker handlerInvoker;
    private final List<HttpMessageConverter<?>> messageConverters;

    public ASEPFilter(SecurityExceptionHandlerMethodRegistry handlerRegistry,
                      SecurityExceptionHandlerInvoker handlerInvoker,
                      List<HttpMessageConverter<?>> messageConverters) {
        this.handlerRegistry = handlerRegistry;
        this.handlerInvoker = handlerInvoker;
        this.messageConverters = (messageConverters != null) ? messageConverters : Collections.emptyList();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (Throwable ex) {
            if (response.isCommitted()) {
                logger.warn("Response already committed. Unable to handle exception: {}", ex.getMessage(), ex);
                return;
            }
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            handleException(request, response, authentication, ex);
        }
    }

    private void handleException(HttpServletRequest request, HttpServletResponse response,
                                 Authentication authentication, Throwable exception) throws IOException {
        try {
            logger.debug("ASEPFilter caught exception: {}, for authentication: {}",
                    exception.getClass().getName(),
                    authentication != null ? authentication.getName() : "null");

            HandlerMethod handlerMethod = handlerRegistry.findBestExceptionHandlerMethod(exception, authentication, request);

            if (handlerMethod != null) {
                logger.debug("Found @SecurityExceptionHandler for {}: {}", exception.getClass().getSimpleName(), handlerMethod);
                MediaType resolvedMediaType = determineResponseMediaType(request, handlerMethod);
                handlerInvoker.invokeHandlerMethod(request, response, authentication, exception, handlerMethod, resolvedMediaType);
            } else {
                logger.debug("No @SecurityExceptionHandler found for {}. Using centralized default error response.",
                        exception.getClass().getSimpleName());
                handleCentralizedDefaultErrorResponse(request, response, exception, authentication, false);
            }
        } catch (Exception handlerException) {
            logger.error("Exception occurred while handling another exception ({}) by @SecurityExceptionHandler: {}",
                    exception.getClass().getSimpleName(), handlerException.getMessage(), handlerException);
            if (!response.isCommitted()) {
                handleCentralizedDefaultErrorResponse(request, response, handlerException, authentication, true);
            } else {
                logger.warn("Response already committed. Unable to send final default error for handlerException: {}",
                        handlerException.getMessage());
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void handleCentralizedDefaultErrorResponse(HttpServletRequest request,
                                                       HttpServletResponse response,
                                                       Throwable exception,
                                                       Authentication authentication,
                                                       boolean isHandlerError) throws IOException {
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        String errorCode = "INTERNAL_SERVER_ERROR";
        String errorMessage = "An unexpected error occurred.";

        if (exception instanceof AuthenticationException) {
            status = HttpStatus.UNAUTHORIZED;
            errorCode = "UNAUTHENTICATED";
            errorMessage = "Authentication failed: " + exception.getMessage();
            SecurityContextHolder.clearContext();
            logger.debug("Cleared SecurityContext due to AuthenticationException.");
        } else if (exception instanceof AccessDeniedException) {
            status = HttpStatus.FORBIDDEN;
            errorCode = "ACCESS_DENIED";
            errorMessage = "Access denied: " + exception.getMessage();
        } else {
            if (isHandlerError) {
                errorMessage = "Error occurred in exception handler: " + exception.getMessage();
            }
        }

        response.setStatus(status.value());
        MediaType bestMatchingMediaType = determineBestMediaTypeForDefaultResponse(request, messageConverters);
        response.setContentType(bestMatchingMediaType.toString());

        Map<String, Object> errorAttributes = new HashMap<>();
        errorAttributes.put("timestamp", System.currentTimeMillis());
        errorAttributes.put("status", status.value());
        errorAttributes.put("error", errorCode);
        errorAttributes.put("message", errorMessage);
        errorAttributes.put("path", request.getRequestURI());
        // 실제로는 더 많은 정보 (예: exception 클래스명 등) 추가 가능

        boolean written = false;
        if (!this.messageConverters.isEmpty()) {
            ServletServerHttpResponse outputMessage = new ServletServerHttpResponse(response);
            for (HttpMessageConverter converter : this.messageConverters) {
                if (converter.canWrite(errorAttributes.getClass(), bestMatchingMediaType)) {
                    try {
                        ((HttpMessageConverter<Object>) converter).write(errorAttributes, bestMatchingMediaType, outputMessage);
                        written = true;
                        break;
                    } catch (IOException e) {
                        logger.error("Error writing default error response with HttpMessageConverter", e);
                    }
                }
            }
        }

        if (!written) {
            logger.warn("No suitable HttpMessageConverter found for default error response (MediaType: {}). Sending plain text.", bestMatchingMediaType);
            response.setContentType(MediaType.TEXT_PLAIN_VALUE); // 명시적으로 text/plain으로 설정
            response.getWriter().write("Status: " + status.value() + "\nError: " + errorCode + "\nMessage: " + errorMessage);
        }

        logger.info("Sent centralized default error response: status={}, type={}, message='{}'",
                status, exception.getClass().getSimpleName(), exception.getMessage());
    }

    private MediaType determineResponseMediaType(HttpServletRequest request, HandlerMethod handlerMethod) {
        if (handlerMethod != null && handlerMethod.getProduces() != null && !handlerMethod.getProduces().isEmpty()) {
            List<MediaType> handlerProduces = handlerMethod.getProduces().stream().map(MediaType::parseMediaType).toList();
            String acceptHeader = request.getHeader(HttpHeaders.ACCEPT);
            if (acceptHeader != null && !acceptHeader.trim().isEmpty()) {
                List<MediaType> acceptedMediaTypes = MediaType.parseMediaTypes(acceptHeader);
                MediaType.sortBySpecificityAndQuality(acceptedMediaTypes);
                for (MediaType acceptedType : acceptedMediaTypes) {
                    for (MediaType producedType : handlerProduces) {
                        if (acceptedType.isCompatibleWith(producedType)) {
                            return producedType.removeQualityValue(); // 클라이언트가 원하는 것 중 핸들러가 제공 가능한 첫번째 것
                        }
                    }
                }
            }
            return handlerProduces.get(0).removeQualityValue(); // Accept 헤더 없거나 매칭 안되면 핸들러의 첫번째 produces
        }
        // 핸들러에 produces 없으면 요청 Accept 헤더 기반으로 시스템 기본 지원 타입 시도
        return determineBestMediaTypeForDefaultResponse(request, this.messageConverters);
    }

    private MediaType determineBestMediaTypeForDefaultResponse(HttpServletRequest request, List<HttpMessageConverter<?>> converters) {
        String acceptHeader = request.getHeader(HttpHeaders.ACCEPT);
        if (acceptHeader != null && !acceptHeader.trim().isEmpty()) {
            List<MediaType> acceptedMediaTypes = MediaType.parseMediaTypes(acceptHeader);
            MediaType.sortBySpecificityAndQuality(acceptedMediaTypes);

            for (MediaType acceptedType : acceptedMediaTypes) {
                for (HttpMessageConverter<?> converter : converters) {
                    for (MediaType supportedMediaType : converter.getSupportedMediaTypes()) {
                        if (acceptedType.isCompatibleWith(supportedMediaType)) {
                            return supportedMediaType.removeQualityValue();
                        }
                    }
                }
            }
            // 매칭되는 컨버터 없으면, 첫번째 acceptedType (와일드카드 아닐 시)
            if(!acceptedMediaTypes.isEmpty() && !acceptedMediaTypes.get(0).isWildcardType()){
                return acceptedMediaTypes.get(0).removeQualityValue();
            }
        }
        return MediaType.APPLICATION_JSON; // 최후의 기본값
    }


    @Override
    public int getOrder() {
        return ASEP_FILTER_ORDER;
    }
}
