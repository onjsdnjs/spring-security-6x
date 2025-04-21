package io.springsecurity.springsecurity6x.jwt.annotation;

import io.springsecurity.springsecurity6x.jwt.configuration.IntegrationAuthAutoConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import(IntegrationAuthAutoConfiguration.class)
public @interface EnableIntegrationAuthPlatform {
}

