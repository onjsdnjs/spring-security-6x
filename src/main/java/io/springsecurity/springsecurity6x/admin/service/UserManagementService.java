package io.springsecurity.springsecurity6x.admin.service;

import io.springsecurity.springsecurity6x.domain.dto.AccountDto;
import io.springsecurity.springsecurity6x.entity.Users;

import java.util.List;

public interface UserManagementService {

    void modifyUser(AccountDto accountDto);

    List<Users> getUsers();
    AccountDto getUser(Long id);

    void deleteUser(Long idx);

}
