package io.springsecurity.springsecurity6x.security.service;

import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true) // 트랜잭션 범위 내에서 지연 로딩된 관계들을 가져오기 위함
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Users, Group, Role, Permission을 모두 FETCH JOIN하여 N+1 쿼리 문제 방지
        Users user = userRepository.findByUsernameWithGroupsRolesAndPermissions(username) // 새로운 쿼리 사용
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username));

        return new CustomUserDetails(user);
    }
}
