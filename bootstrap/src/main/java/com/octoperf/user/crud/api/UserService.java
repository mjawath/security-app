package com.octoperf.user.crud.api;

import com.octoperf.user.entity.User;
import com.octoperf.user.entity.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Created by jawa on 12/24/2020.
 */
@Service
public class UserService  implements UserCrudService,UserDetailsManager {


    @Autowired
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(PasswordEncoder encoder) {
        passwordEncoder =encoder;
    }


    @Override
    public User save(User user) {
        Optional<User> byUsername = findByUsername(user.getUsername());
        byUsername.ifPresent((e)-> new RuntimeException("user already exist"));

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        User saved = userRepository.save(user);
        return saved;

    }

    @Override
    public Optional<User> find(String id) {
        return userRepository.findById(id);
    }

    @Override
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public void createUser(UserDetails userDetails) {
//        this.save(userDetails)
    }

    @Override
    public void updateUser(UserDetails userDetails) {

    }

    @Override
    public void deleteUser(String s) {

    }

    @Override
    public void changePassword(String s, String s1) {

    }

    @Override
    public boolean userExists(String s) {
        return false;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return findByUsername(username).get();
    }
}
