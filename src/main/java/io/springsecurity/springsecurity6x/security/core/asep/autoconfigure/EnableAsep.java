package io.springsecurity.springsecurity6x.security.core.asep.autoconfigure;


import org.springframework.context.annotation.Import;
import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(AsepAutoConfiguration.class)
public @interface EnableAsep {
}
