package com.developerstack.security.service;

import com.developerstack.security.dao.ApplicationUserDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class ApplicationUserServiceImpl implements UserDetailsService {

    private final ApplicationUserDao applicationUserDao;


    @Autowired
    public ApplicationUserServiceImpl(ApplicationUserDao applicationUserDao) {
        this.applicationUserDao = applicationUserDao;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return applicationUserDao.findApplicationUserByUsername(username)
                .orElseThrow(()->new UsernameNotFoundException("Username not found => "+username));
    }
}
