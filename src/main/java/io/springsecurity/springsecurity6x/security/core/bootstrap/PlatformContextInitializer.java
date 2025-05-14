package io.springsecurity.springsecurity6x.security.core.bootstrap;

import io.springsecurity.springsecurity6x.security.core.context.PlatformContext;
import io.springsecurity.springsecurity6x.security.properties.AuthContextProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.util.Objects;

/**
 * PlatformContext에 글로벌 공유 객체를 초기화하는 역할을 담당합니다.
 * SecurityPlatformConfiguration 에서 생성되어 사용됩니다.
 */
public class PlatformContextInitializer {

    private static final Logger log = LoggerFactory.getLogger(PlatformContextInitializer.class);

    private final PlatformContext platformContext;
    private final SecretKey secretKey;
    private final AuthContextProperties authContextProperties;
    // 필요에 따라 ObjectMapper 등 다른 글로벌 공유 객체도 추가 가능

    public PlatformContextInitializer(PlatformContext platformContext,
                                      SecretKey secretKey,
                                      AuthContextProperties authContextProperties) {
        this.platformContext = Objects.requireNonNull(platformContext, "platformContext cannot be null");
        this.secretKey = Objects.requireNonNull(secretKey, "secretKey cannot be null");
        this.authContextProperties = Objects.requireNonNull(authContextProperties, "authContextProperties cannot be null");
    }

    /**
     * PlatformContext에 필요한 글로벌 공유 객체들을 등록합니다.
     */
    public void initializeSharedObjects() {
        log.debug("Initializing global shared objects in PlatformContext.");
        platformContext.share(SecretKey.class, secretKey);
        platformContext.share(AuthContextProperties.class, authContextProperties);
        // 예: platformContext.share(ObjectMapper.class, new ObjectMapper().findAndRegisterModules());
        log.info("Global shared objects (SecretKey, AuthContextProperties) registered in PlatformContext.");
    }
}
