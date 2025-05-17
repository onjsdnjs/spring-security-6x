package io.springsecurity.springsecurity6x.security.core.asep.filter;

import io.springsecurity.springsecurity6x.security.core.asep.handler.AsepHandlerAdapter;
import io.springsecurity.springsecurity6x.security.core.asep.handler.SecurityExceptionHandlerMethodRegistry;
import io.springsecurity.springsecurity6x.security.core.asep.handler.model.HandlerMethod;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.lang.Nullable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.MimeTypeUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * ASEP의 핵심 필터 (POJO).
 * SecurityContext가 설정된 후 발생하는 모든 예외를 포착하고,
 * 주입된 AsepHandlerAdapter를 통해 일관된 방식으로 처리합니다.
 */
public class ASEPFilter extends OncePerRequestFilter implements Ordered { // Spring의 필터 체인에 통합되려면 Ordered는 유용

    private static final Logger logger = LoggerFactory.getLogger(ASEPFilter.class);

    // 이 필터의 순서는 GlobalConfigurer에서 addFilterAfter 시점에 간접적으로 결정되거나,
    // SecurityConfigurer 인터페이스 등을 통해 플랫폼 레벨에서 관리될 수 있음.
    // 여기서는 Ordered 인터페이스를 구현해두어, 만약 다른 방식으로 필터가 등록될 경우를 대비.
    private int order = Ordered.HIGHEST_PRECEDENCE + 100; // 기본값, 외부에서 설정 가능

    private final SecurityExceptionHandlerMethodRegistry handlerRegistry; // 싱글톤 빈 주입
    private final AsepHandlerAdapter handlerAdapter; // 해당 스코프의 POJO 인스턴스 주입
    private final List<HttpMessageConverter<?>> messageConverters; // 공유될 수 있는 HttpMessageConverter 리스트

    public ASEPFilter(SecurityExceptionHandlerMethodRegistry handlerRegistry,
                      AsepHandlerAdapter handlerAdapter,
                      List<HttpMessageConverter<?>> messageConverters) {
        this.handlerRegistry = handlerRegistry;
        this.handlerAdapter = handlerAdapter;
        this.messageConverters = (messageConverters != null) ? messageConverters : Collections.emptyList();
    }

    public void setOrder(int order) {
        this.order = order;
    }

    @Override
    public int getOrder() {
        return this.order;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (Throwable ex) {
            if (response.isCommitted()) {
                logger.warn("Response already committed. Unable to handle exception: {}", ex.getMessage(), ex);
                return;
            }
            // 현재 SecurityContext 에서 Authentication 객체 가져오기
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            handleException(request, response, authentication, ex);
        }
    }

    private void handleException(HttpServletRequest request, HttpServletResponse response,
                                 @Nullable Authentication authentication, Throwable exception) throws IOException {
        try {
            logger.debug("ASEPFilter caught exception: {} for authentication: {}",
                    exception.getClass().getName(),
                    (authentication != null ? authentication.getName() : "null"));

            HandlerMethod handlerMethod = handlerRegistry.findBestExceptionHandlerMethod(exception, authentication, request);

            if (handlerMethod != null) {
                logger.debug("Found ASEP handler for {}: {}", exception.getClass().getSimpleName(), handlerMethod);
                MediaType resolvedMediaType = determineResponseMediaType(request, handlerMethod); // Content Negotiation
                // 주입된 AsepHandlerAdapter 사용
                this.handlerAdapter.invokeHandlerMethod(request, response, authentication, exception, handlerMethod, resolvedMediaType);
            } else {
                logger.debug("No ASEP handler found for {}. Using centralized default error response.",
                        exception.getClass().getSimpleName());
                handleCentralizedDefaultErrorResponse(request, response, exception, authentication, false);
            }
        } catch (Exception handlerInvocationException) {
            // 핸들러 실행 중 새로운 예외 발생 시 처리
            logger.error("Exception occurred while invoking ASEP handler for original exception ({}): {}",
                    exception.getClass().getSimpleName(), handlerInvocationException.getMessage(), handlerInvocationException);
            if (!response.isCommitted()) {
                // 이 경우, 다시 핸들러를 찾지 않고 중앙 기본 오류 응답으로 처리 (무한 루프 방지)
                handleCentralizedDefaultErrorResponse(request, response, handlerInvocationException, authentication, true);
            } else {
                logger.warn("Response already committed. Unable to send final default error for handlerInvocationException: {}",
                        handlerInvocationException.getMessage());
            }
        }
    }

    // determineResponseMediaType, handleCentralizedDefaultErrorResponse 메소드는 이전과 동일하게 유지
    // (단, handleCentralizedDefaultErrorResponse는 this.messageConverters 사용)
    @SuppressWarnings("unchecked")
    private void handleCentralizedDefaultErrorResponse(HttpServletRequest request,
                                                       HttpServletResponse response,
                                                       Throwable exception,
                                                       @Nullable Authentication authentication,
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
                errorMessage = "Error occurred in ASEP exception handler: " + exception.getMessage();
            }
        }

        response.setStatus(status.value());
        MediaType bestMatchingMediaType = determineBestMediaTypeForDefaultResponse(request, this.messageConverters); // this.messageConverters 사용
        response.setContentType(bestMatchingMediaType.toString());

        Map<String, Object> errorAttributes = new HashMap<>();
        errorAttributes.put("timestamp", System.currentTimeMillis());
        errorAttributes.put("status", status.value());
        errorAttributes.put("error", errorCode); // HttpStatus의 reason phrase 대신 사용자 정의 코드
        errorAttributes.put("message", errorMessage); // 실제 환경에서는 XSS 방지 처리 필요
        errorAttributes.put("path", request.getRequestURI());

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
            response.setContentType(MediaType.TEXT_PLAIN_VALUE);
            response.getWriter().write("Status: " + status.value() + "\nError: " + errorCode + "\nMessage: " + errorMessage);
        }

        logger.info("Sent centralized default error response: status={}, type={}, message='{}'",
                status, exception.getClass().getSimpleName(), exception.getMessage());
    }

    private MediaType determineResponseMediaType(HttpServletRequest request, HandlerMethod handlerMethod) {
        // Content Negotiation 로직 (이전과 유사)
        // handlerMethod의 produces와 request의 Accept 헤더를 비교
        // this.messageConverters도 참고하여 최종 결정 가능
        if (handlerMethod != null && handlerMethod.getProduces() != null && !handlerMethod.getProduces().isEmpty()) {
            List<MediaType> handlerProduces = handlerMethod.getProduces().stream().map(MediaType::parseMediaType).toList();
            String acceptHeader = request.getHeader(HttpHeaders.ACCEPT);
            if (acceptHeader != null && !acceptHeader.trim().isEmpty()) {
                try {
                    List<MediaType> acceptedMediaTypes = MediaType.parseMediaTypes(acceptHeader);
                    MimeTypeUtils.sortBySpecificity(acceptedMediaTypes); // 품질 값 및 구체성으로 정렬
                    for (MediaType acceptedType : acceptedMediaTypes) {
                        for (MediaType producedType : handlerProduces) {
                            if (acceptedType.isCompatibleWith(producedType)) {
                                return producedType.removeQualityValue();
                            }
                        }
                    }
                } catch (Exception e) {
                    logger.warn("Could not parse Accept header: {}", acceptHeader, e);
                }
            }
            // Accept 헤더가 없거나 매칭되는 것이 없으면, 핸들러가 명시한 첫 번째 타입을 사용
            return handlerProduces.getFirst().removeQualityValue();
        }
        // 핸들러에 produces가 명시되지 않은 경우, 요청의 Accept 헤더를 기반으로 기본 응답 타입 결정
        return determineBestMediaTypeForDefaultResponse(request, this.messageConverters);
    }

    private MediaType determineBestMediaTypeForDefaultResponse(HttpServletRequest request, List<HttpMessageConverter<?>> converters) {
        // 기본 오류 응답을 위한 Content Negotiation (이전과 유사)
        String acceptHeader = request.getHeader(HttpHeaders.ACCEPT);
        if (acceptHeader != null && !acceptHeader.trim().isEmpty()) {
            try{
                List<MediaType> acceptedMediaTypes = MediaType.parseMediaTypes(acceptHeader);
                MimeTypeUtils.sortBySpecificity(acceptedMediaTypes);

                for (MediaType acceptedType : acceptedMediaTypes) {
                    // JSON 또는 XML을 우선적으로 고려 (실제로는 converters가 지원하는 타입을 확인해야 함)
                    if (acceptedType.isCompatibleWith(MediaType.APPLICATION_JSON)) {
                        return MediaType.APPLICATION_JSON;
                    }
                    if (acceptedType.isCompatibleWith(MediaType.APPLICATION_XML)) {
                        return MediaType.APPLICATION_XML; // 예시
                    }
                    // 다른 지원 타입에 대한 로직 추가 가능
                    // 또는 converters 리스트를 순회하며 첫 번째로 호환되는 타입 반환
                    for (HttpMessageConverter<?> converter : converters) {
                        for (MediaType supportedMediaType : converter.getSupportedMediaTypes(Object.class)) { // Object.class는 일반적인 경우
                            if (acceptedType.isCompatibleWith(supportedMediaType)) {
                                return supportedMediaType.removeQualityValue();
                            }
                        }
                    }
                }
                // 명시적으로 매칭되는 것이 없으면, 첫 번째 acceptedType (와일드카드가 아닐 시)
                if (!acceptedMediaTypes.isEmpty() && !acceptedMediaTypes.getFirst().isWildcardType() && !acceptedMediaTypes.getFirst().isWildcardSubtype()){
                    return acceptedMediaTypes.getFirst().removeQualityValue();
                }
            } catch (Exception e) {
                logger.warn("Could not parse Accept header for default response: {}", acceptHeader, e);
            }
        }
        return MediaType.APPLICATION_JSON;
    }
}
