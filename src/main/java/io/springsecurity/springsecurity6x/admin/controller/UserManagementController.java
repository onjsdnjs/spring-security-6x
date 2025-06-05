package io.springsecurity.springsecurity6x.admin.controller;

import io.springsecurity.springsecurity6x.admin.service.RoleService;
import io.springsecurity.springsecurity6x.admin.service.UserManagementService;
import io.springsecurity.springsecurity6x.domain.dto.AccountDto;
import io.springsecurity.springsecurity6x.domain.dto.UserDto;
import io.springsecurity.springsecurity6x.entity.Users;
import io.springsecurity.springsecurity6x.entity.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Controller
@RequiredArgsConstructor
@RequestMapping("/admin/users")
public class UserManagementController {
	private final UserManagementService userManagementService;
	private final RoleService roleService;
	@GetMapping
	public String getUsers(Model model) {

		List<Users> users = userManagementService.getUsers();
		model.addAttribute("users", users);

		return "admin/users";
	}

	@PostMapping
	public String modifyUser(UserDto userDto) {

		userManagementService.modifyUser(userDto);

		return "redirect:/admin/users";
	}

	@GetMapping(value = "/{id}")
	public String getUser(@PathVariable(value = "id") Long id, Model model) {

		UserDto userDto = userManagementService.getUser(id);
		List<Role> roleList = roleService.getRolesWithoutExpression();

		model.addAttribute("user", userDto);
		model.addAttribute("roleList", roleList);

		return "admin/userdetails";
	}

	@GetMapping(value = "/delete/{id}")
	public String removeUser(@PathVariable(value = "id") Long id) {

		userManagementService.deleteUser(id);

		return "redirect:admin/users";
	}
}
