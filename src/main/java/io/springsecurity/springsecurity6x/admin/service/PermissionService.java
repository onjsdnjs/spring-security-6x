package io.springsecurity.springsecurity6x.admin.service;

import io.springsecurity.springsecurity6x.entity.Permission;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

public interface PermissionService {
    Permission createPermission(Permission permission);
    Optional<Permission> getPermission(Long id);
    List<Permission> getAllPermissions();
    void deletePermission(Long id);
    Permission updatePermission(Permission permission);
    Optional<Permission> findByName(String name);
}
