package com.octoperf.user.entity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Created by jawa on 12/24/2020.
 */
@Repository
public interface UserRepository extends JpaRepository<User,String>{

    User save(User user);


    Optional<User> findByUsername(String username);
}
