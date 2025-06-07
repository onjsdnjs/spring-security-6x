package io.springsecurity.springsecurity6x.security.service;

import io.springsecurity.springsecurity6x.security.persist.UrlRoleMapper;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class DynamicAuthorizationService {
    private final UrlRoleMapper delegate;

    public DynamicAuthorizationService(UrlRoleMapper delegate) {
        this.delegate = delegate;
    }
    public Map<String, String> getUrlRoleMappings() {
            return delegate.getUrlRoleMappings();
    }
}
