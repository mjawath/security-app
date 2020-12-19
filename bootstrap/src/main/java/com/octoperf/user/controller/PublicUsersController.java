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

  class  LoginDTO{
    String foo;
    String bar;

    public String getFoo() {
      return foo;
    }

    public void setFoo(String foo) {
      this.foo = foo;
    }
  }

  @PostMapping("/register")
  String register(
    @RequestParam("foo") final String username,
    @RequestParam("bar") final String password) {
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
    @RequestParam("foo") final String username,
    @RequestParam("bar") final String password) {
    return authentication
      .login(username, password)
      .orElseThrow(() -> new RuntimeException("invalid login and/or bar"));
  }


  @PostMapping("/v1/login")
  String login(
          @RequestBody LoginDTO user) {

    return authentication
            .login(user.foo, user.bar)
            .orElseThrow(() -> new RuntimeException("invalid login and/or bar"));
  }
}
