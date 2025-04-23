package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.domain.UserDto;
import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;


    @GetMapping("/register")
    public String registerPage(Model model) {
        return "register";
    }

    @PostMapping("/api/register")
    @ResponseBody
    public ResponseEntity<String> processRegister(@ModelAttribute UserDto userDto) {

        Users users = modelMapper.map(userDto, Users.class);
        userRepository.save(users);

        return ResponseEntity.ok().body("success");
    }

    @GetMapping("/users")
    public String usersPage(Model model) {
        return "users";
    }

    @GetMapping("/api/users")
    public ResponseEntity<List<UserDto>> users() {
        List<UserDto> users = userRepository.findAll().stream()
                .map(user -> modelMapper.map(user, UserDto.class))
                .toList();
        return ResponseEntity.ok().body(users);
    }

}
