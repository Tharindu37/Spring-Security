package com.developerstack.security.config.permission;

import com.google.common.collect.Sets;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

import static com.developerstack.security.config.permission.ApplicationUserPermission.*;

public enum ApplicationUserRole {
    USER(Sets.newHashSet(ORDER_WRITE,PRODUCT_READ,CUSTOMER_WRITE,CUSTOMER_READ)),
    ADMIN(Sets.newHashSet(ORDER_WRITE,ORDER_READ,CUSTOMER_READ,CUSTOMER_WRITE,PRODUCT_READ,PRODUCT_WRITE)),
    MANAGER(Sets.newHashSet(ORDER_READ,PRODUCT_READ,PRODUCT_WRITE,CUSTOMER_READ));

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions(){
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities(){
        Set<SimpleGrantedAuthority> permissions = getPermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
        return permissions;
    }
}
