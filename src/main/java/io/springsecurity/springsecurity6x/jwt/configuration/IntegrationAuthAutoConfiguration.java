package io.springsecurity.springsecurity6x.jwt.configuration;

import io.springsecurity.springsecurity6x.jwt.properties.IntegrationAuthProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@EnableConfigurationProperties(IntegrationAuthProperties.class)
@Import({JwtSecurityAutoConfiguration.class})
public class IntegrationAuthAutoConfiguration {
}

