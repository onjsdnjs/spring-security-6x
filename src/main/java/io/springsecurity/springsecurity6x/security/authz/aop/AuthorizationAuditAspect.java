package io.springsecurity.springsecurity6x.security.authz.aop;

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

import java.util.function.Supplier;

/**
 * 인가 결정 과정을 감사하기 위한 AOP Aspect.
 * 'authorization-audit'라는 별도의 로거를 사용하여 모든 인가 시도와 결과를 기록합니다.
 */
@Aspect
@Component
public class AuthorizationAuditAspect {

    private static final Logger auditLogger = LoggerFactory.getLogger("authorization-audit");

    /**
     * CustomDynamicAuthorizationManager의 check 메서드 실행 전에 호출되어 인가 시도를 로깅합니다.
     */
    @Before("execution(* io.springsecurity.springsecurity6x.security.authz.manager.CustomDynamicAuthorizationManager.check(..))")
    public void logAuthorizationAttempt(JoinPoint joinPoint) {
        Object[] args = joinPoint.getArgs();
        if (args.length > 1 && args[1] instanceof RequestAuthorizationContext ctx) {
            HttpServletRequest request = ctx.getRequest();
            auditLogger.info("[AUTH_ATTEMPT] URI=[{}], Method=[{}], Principal=[{}], IP=[{}]",
                    request.getRequestURI(),
                    request.getMethod(),
                    getPrincipalName(args[0]),
                    request.getRemoteAddr()
            );
        }
    }

    /**
     * CustomDynamicAuthorizationManager의 check 메서드 실행 후에 호출되어 인가 결과를 로깅합니다.
     */
    @AfterReturning(pointcut = "execution(* io.springsecurity.springsecurity6x.security.authz.manager.CustomDynamicAuthorizationManager.check(..))", returning = "decision")
    public void logAuthorizationResult(JoinPoint joinPoint, AuthorizationDecision decision) {
        Object[] args = joinPoint.getArgs();
        if (args.length > 1 && args[1] instanceof RequestAuthorizationContext ctx) {
            auditLogger.info("[AUTH_RESULT] URI=[{}], Principal=[{}], Granted=[{}]",
                    ctx.getRequest().getRequestURI(),
                    getPrincipalName(args[0]),
                    decision != null && decision.isGranted()
            );
        }
    }

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