package io.springsecurity.springsecurity6x.service;

import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.OAuth2StateConfigurer;
import io.springsecurity.springsecurity6x.security.dsl.state.oauth2.client.OAuth2ResourceClient;
import org.springframework.stereotype.Service;

@Service
public class ResourceAccessService {

    private final OAuth2ResourceClient resourceClient;

    public ResourceAccessService(OAuth2StateConfigurer oauth2StateConfigurer) {
        this.resourceClient = oauth2StateConfigurer.resourceClient();
    }

    public String callSecureApi() {
        return resourceClient.get("http://localhost:8081/api/secure", String.class);
    }
}



