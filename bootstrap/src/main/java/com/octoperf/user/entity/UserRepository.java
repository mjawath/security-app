package com.octoperf.user.entity;

import java.util.Optional;

/**
 * Created by jawa on 12/24/2020.
 */
public interface UserRepository {

    User save(User user);

    Optional<User> find(String id);

    Optional<User> findByUsername(String username);
}
