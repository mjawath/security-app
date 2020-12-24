package com.octoperf.user.crud.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

/**
 * Created by jawa on 12/25/2020.
 */
public class UserAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    PasswordEncoder passwordEncoder;
    private UserDetailsManager userDetailsService;

    @Autowired
    public UserAuthenticationProvider(PasswordEncoder pe) {
        this.passwordEncoder = pe;
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) throws AuthenticationException {

    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) throws AuthenticationException {
        UserDetails  ud =userDetailsService.loadUserByUsername(username);

        //verify password
        return ud;
    }

    @Autowired
    public void setUserDetailsService(UserDetailsManager userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
}
