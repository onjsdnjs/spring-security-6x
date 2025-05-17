package io.springsecurity.springsecurity6x.security.core.asep.annotation;

import java.lang.annotation.*;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface SecurityExceptionHandler {
    Class<? extends Throwable>[] value() default {};
    int priority() default Integer.MAX_VALUE;
    String[] produces() default {};
}
