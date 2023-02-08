package com.developerstack.security.dao.impl;

import com.developerstack.security.dao.ApplicationUserDao;
import com.developerstack.security.dto.ApplicationUser;
import com.google.common.collect.Lists;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.developerstack.security.config.permission.ApplicationUserRole.*;

@Repository
public class ApplicationUserDaoImpl implements ApplicationUserDao {
    /*actual database*/

    private final PasswordEncoder passwordEncoder;

    public ApplicationUserDaoImpl(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> findApplicationUserByUsername(String username) {
        return getApplicationUsers().stream().filter(e->e.getUsername().equals(username)).findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers= Lists.newArrayList(
                //tharaka,nalaka,ayesh
                new ApplicationUser(
                        USER.getGrantedAuthorities(),
                        "tharaka",
                        passwordEncoder.encode("1234"),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        MANAGER.getGrantedAuthorities(),
                        "ayesh",
                        passwordEncoder.encode("1234"),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        ADMIN.getGrantedAuthorities(),
                        "nalaka",
                        passwordEncoder.encode("1234"),
                        true,
                        true,
                        true,
                        true
                )
        );
        return applicationUsers;
    }
}
