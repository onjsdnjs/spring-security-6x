package io.springsecurity.springsecurity6x.admin.service;

import io.springsecurity.springsecurity6x.entity.Resources;
import io.springsecurity.springsecurity6x.entity.Role;

import java.util.List;
import java.util.Set;

public interface ResourcesService {
    Resources getResources(long id);
    List<Resources> getResources();
    Resources createResources(Resources resources, Set<Role> roles) ;
    Resources updateResources(Resources resources, Set<Role> roles);
    void deleteResources(long id);
}
