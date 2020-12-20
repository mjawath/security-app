package com.octoperf.user.controller;

import com.octoperf.auth.api.UserAuthenticationService;
import com.octoperf.user.crud.api.UserCrudService;
import com.octoperf.user.entity.User;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.*;

import static lombok.AccessLevel.PACKAGE;
import static lombok.AccessLevel.PRIVATE;

@RestController
@RequestMapping("/public/users")
@FieldDefaults(level = PRIVATE, makeFinal = true)
@AllArgsConstructor(access = PACKAGE)
final class PublicUsersController {
  @NonNull
  UserAuthenticationService authentication;
  @NonNull
  UserCrudService users;

  static class  LoginDTO{
    String username;
    String password;

    public String getUsername() {
      return username;
    }

    public void setUsername(String username) {
      this.username = username;
    }

    public String getPassword() {
      return password;
    }

    public void setPassword(String password) {
      this.password = password;
    }
  }

  @PostMapping("/register")
  String register(
    @RequestParam("username") final String username,
    @RequestParam("password") final String password) {
    users
      .save(
        User
          .builder()
          .id(username)
          .username(username)
          .password(password)
          .build()
      );

    return login(username, password);
  }

  @PostMapping("/login")
  String login(
    @RequestParam("username") final String username,
    @RequestParam("password") final String password) {
    return authentication
      .login(username, password)
      .orElseThrow(() -> new RuntimeException("invalid login and/or password"));
  }


  @PostMapping("/v1/login")
  String login(
          @RequestBody LoginDTO user) {
    System.out.println(user.getUsername());

    return authentication
            .login(user.username, user.password)
            .orElseThrow(() -> new RuntimeException("invalid login and/or password"));
  }
}
