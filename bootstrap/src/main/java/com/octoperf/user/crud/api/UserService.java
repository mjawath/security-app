package com.octoperf.user.crud.api;

import com.octoperf.user.entity.User;
import com.octoperf.user.entity.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.util.Optional;

/**
 * Created by jawa on 12/24/2020.
 */
@Service
public class UserService extends JdbcUserDetailsManager implements UserCrudService {


    @Autowired
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(DataSource dataSource,PasswordEncoder encoder) {
        passwordEncoder =encoder;
        this.setDataSource(dataSource);
//        setEnableAuthorities(false);
//        setEnableGroups(false);
    }


    @Override
    public User save(User user) {
//        org.springframework.security.core.userdetails.User byUsername = (org.springframework.security.core.userdetails.User)
//                super.loadUserByUsername(user.getUsername());

//
//        if(byUsername!=null){
//            throw new RuntimeException("use already exist");
//        }
//        user.setPassword(passwordEncoder.encode(user.getPassword()));
//
//        super.createUser(user);
//
//
//        UserDetails userDetails = super.loadUserByUsername(user.getUsername());
//        return  new User("",userDetails.getUsername());
        Optional<User> byUsername = findByUsername(user.getUsername());

        byUsername.ifPresent((e)-> new RuntimeException("use already exist"));

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

}
