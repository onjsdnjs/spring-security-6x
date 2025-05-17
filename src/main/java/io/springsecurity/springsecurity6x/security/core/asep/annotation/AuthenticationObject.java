package io.springsecurity.springsecurity6x.security.core.asep.annotation;

import java.lang.annotation.*;

@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuthenticationObject {
}
