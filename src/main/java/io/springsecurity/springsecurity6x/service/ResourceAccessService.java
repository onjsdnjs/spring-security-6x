package io.springsecurity.springsecurity6x.service;

import io.springsecurity.springsecurity6x.security.dsl.oauth2client.OAuth2ClientDsl;
import io.springsecurity.springsecurity6x.security.dsl.oauth2client.client.OAuth2ResourceClient;
import org.springframework.stereotype.Service;

@Service
public class ResourceAccessService {

    private final OAuth2ResourceClient resourceClient;

    public ResourceAccessService(OAuth2ClientDsl oauth2ClientDsl) {
        this.resourceClient = oauth2ClientDsl.resourceClient();
    }

    public String callSecureApi() {
        return resourceClient.get("http://localhost:8081/api/secure", String.class);
    }
}



