package io.springsecurity.springsecurity6x.admin.service;

import io.springsecurity.springsecurity6x.entity.Resources;

import java.util.List;

public interface ResourcesService {
    Resources getResources(long id);
    List<Resources> getResources();

    void createResources(Resources Resources);

    void deleteResources(long id);
}
