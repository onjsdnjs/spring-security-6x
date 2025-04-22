package io.springsecurity.springsecurity6x.domain;

import lombok.Data;

@Data
public class UserDto {

    private String username;
    private String password;
    private String role;
}
