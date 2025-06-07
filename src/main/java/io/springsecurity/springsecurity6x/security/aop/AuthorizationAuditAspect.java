package io.springsecurity.springsecurity6x.security.aop;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.stream.Collectors;

@Aspect
@Component
@Slf4j
public class AuthorizationAuditAspect {
    /**
     * URL 기반 인가 결정 전에 호출됩니다.
     */
    @Before("execution(* io.springsecurity.springsecurity6x.security.manager.CustomDynamicAuthorizationManager.check(..))")
    public void logBeforeUrlAuthorization(JoinPoint joinPoint) {
        Object[] args = joinPoint.getArgs();
        if (args.length > 1 && args[1] instanceof RequestAuthorizationContext ctx) {
            HttpServletRequest request = ctx.getRequest();
            log.info("[URL_AUTH_ATTEMPT] URI: {}, Method: {}, Principal: {}",
                    request.getRequestURI(),
                    request.getMethod(),
                    getPrincipalName(args[0])
            );
        }
    }

    /**
     * URL 기반 인가 결정 후에 호출됩니다.
     */
    @AfterReturning(pointcut = "execution(* io.springsecurity.springsecurity6x.security.manager.CustomDynamicAuthorizationManager.check(..))", returning = "decision")
    public void logAfterUrlAuthorization(JoinPoint joinPoint, AuthorizationDecision decision) {
        Object[] args = joinPoint.getArgs();
        if (args.length > 1 && args[1] instanceof RequestAuthorizationContext ctx) {
            log.info("[URL_AUTH_RESULT] URI: {}, Principal: {}, Granted: {}",
                    ctx.getRequest().getRequestURI(),
                    getPrincipalName(args[0]),
                    decision != null && decision.isGranted()
            );
        }
    }

    /**
     * 데이터 수준 권한 평가(hasPermission) 후에 호출됩니다.
     */
    @AfterReturning(pointcut = "execution(* io.springsecurity.springsecurity6x.security.permission.CustomPermissionEvaluator.hasPermission(..))", returning = "granted")
    public void logAfterPermissionEvaluation(JoinPoint joinPoint, boolean granted) {
        Object[] args = joinPoint.getArgs();
        String argsString = Arrays.stream(args)
                .map(arg -> arg != null ? arg.toString() : "null")
                .collect(Collectors.joining(", "));

        log.info("[PERMISSION_EVAL_RESULT] Method: {}, Args: [{}], Granted: {}",
                joinPoint.getSignature().toShortString(),
                argsString,
                granted
        );
    }

    private String getPrincipalName(Object authSupplier) {
        if (authSupplier instanceof java.util.function.Supplier) {
            Authentication auth = ((java.util.function.Supplier<Authentication>) authSupplier).get();
            if (auth != null) {
                return auth.getName();
            }
        }
        return "anonymous";
    }
}
