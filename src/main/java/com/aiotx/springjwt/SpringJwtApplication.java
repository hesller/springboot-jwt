package com.aiotx.springjwt;

import com.aiotx.springjwt.domain.Role;
import com.aiotx.springjwt.domain.User;
import com.aiotx.springjwt.security.ApplicationUserRole;
import com.aiotx.springjwt.services.Service;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static com.aiotx.springjwt.security.ApplicationUserRole.*;

@SpringBootApplication
public class SpringJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringJwtApplication.class, args);
    }

    @Bean
    CommandLineRunner run(Service userService) {
        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveUser(new User( "John travolta", "john", "123456"));
            userService.saveUser(new User( "Will travolta", "will", "123456"));
            userService.saveUser(new User( "Mark travolta", "mark", "123456"));

            userService.addRoleToUser("john", ADMIN.getRole());
            userService.addRoleToUser("john", ADMIN.getRole());
            userService.addRoleToUser("will", SUPER_ADMIN.getRole());
            userService.addRoleToUser("mark", USER.getRole());
        };
    }



}
