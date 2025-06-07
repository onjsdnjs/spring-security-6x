package io.springsecurity.springsecurity6x.security.authz.aop;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

@Aspect
@Component
public class AuthorizationAuditAspect {

    private static final Logger auditLogger = LoggerFactory.getLogger("authorization-audit");
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Before("execution(* io.springsecurity.springsecurity6x.security.authz.manager.CustomDynamicAuthorizationManager.check(..))")
    public void logAuthorizationAttempt(JoinPoint joinPoint) {
        // ... (이전과 동일)
    }

    @AfterReturning(pointcut = "execution(* io.springsecurity.springsecurity6x.security.authz.manager.CustomDynamicAuthorizationManager.check(..))", returning = "decision")
    public void logAuthorizationResult(JoinPoint joinPoint, AuthorizationDecision decision) {
        Object[] args = joinPoint.getArgs();
        if (args.length > 1 && args[1] instanceof RequestAuthorizationContext ctx) {
            HttpServletRequest request = ctx.getRequest();
            boolean granted = decision != null && decision.isGranted();

            // <<< 핵심 개선: 로그를 JSON 형식으로 구조화 >>>
            Map<String, Object> logData = new HashMap<>();
            logData.put("timestamp", LocalDateTime.now().toString());
            logData.put("type", "AUTH_RESULT");
            logData.put("principal", getPrincipalName(args[0]));
            logData.put("uri", request.getRequestURI());
            logData.put("method", request.getMethod());
            logData.put("remoteIp", request.getRemoteAddr());
            logData.put("granted", granted);

            try {
                auditLogger.info(objectMapper.writeValueAsString(logData));
            } catch (Exception e) {
                auditLogger.error("Failed to write audit log as JSON", e);
            }
        }
    }

    // ... (getPrincipalName 메서드는 동일)
    private String getPrincipalName(Object authSupplier) {
        if (authSupplier instanceof Supplier) {
            Authentication auth = ((Supplier<Authentication>) authSupplier).get();
            if (auth != null) {
                return auth.getName();
            }
        }
        return "anonymous";
    }
}