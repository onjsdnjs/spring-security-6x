package io.springsecurity.springsecurity6x.admin.service.impl;

import io.springsecurity.springsecurity6x.admin.repository.RoleRepository;
import io.springsecurity.springsecurity6x.admin.repository.UserManagementRepository;
import io.springsecurity.springsecurity6x.admin.service.UserManagementService;
import io.springsecurity.springsecurity6x.domain.dto.AccountDto;
import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.entity.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service("userManagementService")
@RequiredArgsConstructor
public class UserManagementServiceImpl implements UserManagementService {

    private final UserManagementRepository userManagementRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    @Override
    public void modifyUser(AccountDto accountDto){
        ModelMapper modelMapper = new ModelMapper();
        Users users = modelMapper.map(accountDto, Users.class);

        if(accountDto.getRoles() != null){
            Set<Role> roles = new HashSet<>();
            accountDto.getRoles().forEach(role -> {
                Optional<Role> r = roleRepository.findByRoleName(role);
                roles.add(r.orElseGet(Role::new));
            });
            users.setUserRoles(roles);
        }
        users.setPassword(passwordEncoder.encode(accountDto.getPassword()));
        userManagementRepository.save(users);
    }

    @Transactional
    public AccountDto getUser(Long id) {
        Users users = userManagementRepository.findById(id).orElse(new Users());
        ModelMapper modelMapper = new ModelMapper();
        AccountDto accountDto = modelMapper.map(users, AccountDto.class);

        List<String> roles = users.getUserRoles()
                .stream()
                .map(Role::getRoleName)
                .collect(Collectors.toList());

        accountDto.setRoles(roles);
        return accountDto;
    }

    @Transactional
    public List<Users> getUsers() {
        return userManagementRepository.findAll();
    }

    @Override
    public void deleteUser(Long id) {
        userManagementRepository.deleteById(id);
    }

}