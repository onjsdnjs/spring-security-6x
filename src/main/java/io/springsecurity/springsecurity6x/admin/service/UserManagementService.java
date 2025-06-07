package io.springsecurity.springsecurity6x.admin.service;

import io.springsecurity.springsecurity6x.domain.dto.UserDto;
import io.springsecurity.springsecurity6x.entity.Users;

import java.util.List;

public interface UserManagementService {

    void modifyUser(UserDto userDto);

    List<Users> getUsers();
    UserDto getUser(Long id);

    void deleteUser(Long idx);

}
