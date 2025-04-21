package io.springsecurity.springsecurity6x.jwt.properties;

import io.springsecurity.springsecurity6x.jwt.enums.AuthType;
import io.springsecurity.springsecurity6x.jwt.enums.TokenType;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.EnumSet;
import java.util.Set;

@Data
@Configuration
@ConfigurationProperties(prefix = "spring.auth")
public class IntegrationAuthProperties {
    private TokenType tokenType = TokenType.EXTERNAL;

    private ExternalTokenSettings external = new ExternalTokenSettings();
    private InternalTokenSettings internal = new InternalTokenSettings();

    private Set<AuthType> enabledAuthTypes = EnumSet.of(AuthType.FORM);

    public boolean isAuthEnabled(AuthType type) {
        return enabledAuthTypes.contains(type);
    }

}
