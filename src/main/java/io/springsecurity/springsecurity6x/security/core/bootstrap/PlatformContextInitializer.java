package io.springsecurity.springsecurity6x.security.core.bootstrap;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.util.Objects;

@Slf4j
public class PlatformContextInitializer {

    private final PlatformContext platformContext;
    private final SecretKey secretKey;
    private final AuthContextProperties authContextProperties;
    private final ObjectMapper objectMapper;

    public PlatformContextInitializer(PlatformContext platformContext,
                                      SecretKey secretKey,
                                      AuthContextProperties authContextProperties,
                                      ObjectMapper objectMapper) { // ObjectMapper 주입 추가
        this.platformContext = Objects.requireNonNull(platformContext, "platformContext cannot be null");
        this.secretKey = Objects.requireNonNull(secretKey, "secretKey cannot be null");
        this.authContextProperties = Objects.requireNonNull(authContextProperties, "authContextProperties cannot be null");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper cannot be null");
    }

    public void initializeSharedObjects() {
        log.debug("Initializing global shared objects in PlatformContext.");
        platformContext.share(SecretKey.class, secretKey);
        platformContext.share(AuthContextProperties.class, authContextProperties);
        platformContext.share(ObjectMapper.class, objectMapper);
        log.info("Global shared objects (SecretKey, AuthContextProperties, ObjectMapper) registered in PlatformContext.");
    }
}
