package io.springsecurity.springsecurity6x.security.core.asep.exception;

import io.springsecurity.springsecurity6x.security.core.asep.annotation.SecurityControllerAdvice;
import io.springsecurity.springsecurity6x.security.core.asep.annotation.SecurityExceptionHandler;
import org.springframework.context.annotation.Configuration;

@SecurityControllerAdvice
@Configuration
public class SecurityExceptionHandlerAdvice {

    @SecurityExceptionHandler
    public void handleException(IllegalArgumentException e) {
        System.out.println("e = " + e);
    }
}
