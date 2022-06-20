package com.aiotx.springjwt.services;

import com.aiotx.springjwt.domain.Role;
import com.aiotx.springjwt.domain.User;
import com.aiotx.springjwt.repository.RoleRepository;
import com.aiotx.springjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@org.springframework.stereotype.Service @RequiredArgsConstructor @Transactional @Slf4j
public class ServiceImplementation implements Service {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Override
    public User saveUser(User user) {
        log.info("Saving new user to the database");
        return userRepository.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role {} to the database", role.getName());

        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String userName, String roleName) {
        User user = userRepository.findByUsername(userName);
        Role role = roleRepository.findByName(roleName);
        log.info("Adding role {} to the user {}", roleName, userName);
        user.getRoles().add(role);
    }

    @Override
    public User getUser(String username) {
        log.info("Fetching user {} ", username);

        return userRepository.findByUsername(username);
    }

    @Override
    public List<User> getUsers() {
        log.info("Fetching all users.");
        return userRepository.findAll();
    }
}
