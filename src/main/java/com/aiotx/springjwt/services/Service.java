package com.aiotx.springjwt.services;

import com.aiotx.springjwt.domain.Role;
import com.aiotx.springjwt.domain.User;

import java.util.List;

public interface Service {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String userName, String roleName);
    User getUser(String username);
    List<User> getUsers();

    List<Role> getRoles();
}
