package com.octoperf.user.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.mycompany.entitybase.BaseEntityString;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.Entity;
import javax.persistence.Table;
import java.util.ArrayList;
import java.util.Collection;

import static java.util.Objects.requireNonNull;

@Data
@Builder
@EqualsAndHashCode(callSuper = true)
@Entity
@Table(name = "users")
@NoArgsConstructor

public class User extends BaseEntityString implements UserDetails {
  private static final long serialVersionUID = 2396654715019746670L;


  String username;
  String password;


  @JsonCreator
  User(@JsonProperty("id") final String id,
       @JsonProperty("username") final String username,
       @JsonProperty("password") final String password) {
    super();
    this.id = id;
    this.username = (username);
    this.password = (password);
  }

  public User(String id,String username){
    this.id = id;
    this.username = username;
  }


  @JsonIgnore
  @Override
  public Collection<GrantedAuthority> getAuthorities() {
    return new ArrayList<>();
  }

  @JsonIgnore
  @Override
  public String getPassword() {
    return password;
  }

  @JsonIgnore
  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @JsonIgnore
  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @JsonIgnore
  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }

}
