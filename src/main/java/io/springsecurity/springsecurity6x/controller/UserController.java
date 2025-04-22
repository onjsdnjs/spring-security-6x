package io.springsecurity.springsecurity6x.controller;

import io.springsecurity.springsecurity6x.domain.UserDto;
import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.List;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;


    @GetMapping("/register")
    public String registerPage(Model model) {
        return "register";
    }

    @PostMapping("/register")
    public String processRegister(@ModelAttribute UserDto userDto) {

        Users users = modelMapper.map(userDto, Users.class);
        userRepository.save(users);

        return "redirect:/users";
    }

    @GetMapping("/users")
    public String userListPage(Model model) {
        List<Users> users = userRepository.findAll();
        model.addAttribute("users", users);
        return "users";
    }
}
