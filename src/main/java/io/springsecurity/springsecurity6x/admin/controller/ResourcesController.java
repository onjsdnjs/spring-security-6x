package io.springsecurity.springsecurity6x.admin.controller;

import io.springsecurity.springsecurity6x.admin.repository.RoleRepository;
import io.springsecurity.springsecurity6x.admin.service.ResourcesService;
import io.springsecurity.springsecurity6x.admin.service.RoleService;
import io.springsecurity.springsecurity6x.domain.dto.ResourcesDto;
import io.springsecurity.springsecurity6x.entity.Resources;
import io.springsecurity.springsecurity6x.entity.Role;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.*;

@Controller
@RequestMapping("/admin/resources")
@RequiredArgsConstructor
public class ResourcesController {

	private final ResourcesService resourcesService;
	private final RoleRepository roleRepository;
	private final RoleService roleService;

	@GetMapping
	public String getResources(Model model) {
		List<Resources> resources = resourcesService.getResources();
		model.addAttribute("resources", resources);

		return "admin/resources";
	}

	@PostMapping
	public String createResources(ResourcesDto resourcesDto) {
		ModelMapper modelMapper = new ModelMapper();
		Optional<Role> role = roleRepository.findByRoleName(resourcesDto.getRoleName());
		Set<Role> roles = new HashSet<>();
		roles.add(role.orElse(new Role()));
		Resources resources = modelMapper.map(resourcesDto, Resources.class);
		resources.setRoleSet(roles);

		resourcesService.createResources(resources);

		return "redirect:/admin/resources";
	}

	@GetMapping(value="/register")
	public String resourcesRegister(Model model) {

		List<Role> roleList = roleService.getRoles();
		model.addAttribute("roleList", roleList);
		List<String> myRoles = new ArrayList<>();
		model.addAttribute("myRoles", myRoles);
		ResourcesDto resources = new ResourcesDto();
		Set<Role> roleSet = new HashSet<>();
		roleSet.add(new Role());
		resources.setRoleSet(roleSet);
		model.addAttribute("resources", resources);

		return "admin/resourcesdetails";
	}

	@GetMapping(value="/{id}")
	public String resourceDetails(@PathVariable String id, Model model) {

		List<Role> roleList = roleService.getRoles();
		model.addAttribute("roleList", roleList);
		Resources resources = resourcesService.getResources(Long.parseLong(id));
		List<String> myRoles = resources.getRoleSet().stream().map(role -> role.getRoleName()).toList();
		model.addAttribute("myRoles", myRoles);
		ModelMapper modelMapper = new ModelMapper();
		ResourcesDto resourcesDto = modelMapper.map(resources, ResourcesDto.class);
		model.addAttribute("resources", resourcesDto);

		return "admin/resourcesdetails";
	}

	@GetMapping(value="/delete/{id}")
	public String removeResources(@PathVariable String id) throws Exception {

		resourcesService.deleteResources(Long.parseLong(id));

		return "redirect:/admin/resources";
	}
}
