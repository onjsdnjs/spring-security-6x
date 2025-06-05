package io.springsecurity.springsecurity6x.security.service;

import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.entity.Role; // Role 엔티티 import
import io.springsecurity.springsecurity6x.entity.Permission; // Permission 엔티티 import
import io.springsecurity.springsecurity6x.security.filter.MfaGrantedAuthority;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet; // HashSet import
import java.util.Set; // Set import


public class CustomUserDetails implements UserDetails {

    private final Users users;
    private final Set<GrantedAuthority> authorities; // GrantedAuthority를 미리 생성하여 저장

    public CustomUserDetails(Users users) {
        this.users = users;
        this.authorities = new HashSet<>(); // HashSet으로 초기화

        if (users.getUserRoles() != null) {
            for (Role role : users.getUserRoles()) {
                // RoleName에 "ROLE_" 프리픽스를 붙여 GrantedAuthority로 추가
                this.authorities.add(new MfaGrantedAuthority("ROLE_" + role.getRoleName().toUpperCase()));

                // 2. Role에 연결된 Permissions 추가
                if (role.getPermissions() != null) {
                    for (Permission perm : role.getPermissions()) {
                        // Permission의 name (예: DOCUMENT_READ)을 GrantedAuthority로 추가
                        this.authorities.add(new MfaGrantedAuthority(perm.getName().toUpperCase()));
                    }
                }
            }
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities; // 미리 생성된 권한 리스트 반환
    }

    public Users getAccount() {
        return users;
    }

    @Override
    public String getPassword() {
        return users.getPassword();
    }

    @Override
    public String getUsername() {
        return users.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}