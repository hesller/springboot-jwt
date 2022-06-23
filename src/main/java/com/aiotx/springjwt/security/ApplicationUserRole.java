package com.aiotx.springjwt.security;

import com.google.common.collect.Sets;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

import static com.aiotx.springjwt.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
    SUPER_ADMIN("SUPER_ADMIN", Sets.newHashSet( SUPER_ADMIN_WRITE, SUPER_ADMIN_READ, ADMIN_WRITE, ADMIN_READ, MANAGER_READ, MANAGER_WRITE, USER_READ, USER_WRITE)),
    ADMIN("ADMIN", Sets.newHashSet(ADMIN_READ, MANAGER_READ, MANAGER_WRITE, USER_READ, USER_WRITE)),
    MANAGER("MANAGER", Sets.newHashSet(USER_READ, USER_WRITE)),
    USER("USER", Sets.newHashSet(USER_READ));

    private final String role;
    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(String role, Set<ApplicationUserPermission> permissions) {
        this.role = role;
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }

    public String getRole() {
        return role;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
        Set<SimpleGrantedAuthority> permissions = this.getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_" + this.getRole()));
        return permissions;
    }
}
