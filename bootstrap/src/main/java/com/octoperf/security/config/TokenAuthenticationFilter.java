package com.octoperf.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.octoperf.token.jwt.JWTTokenService;
import com.octoperf.user.entity.User;
import lombok.experimental.FieldDefaults;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;

import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static java.util.Optional.ofNullable;
import static lombok.AccessLevel.PRIVATE;
import static org.apache.commons.lang3.StringUtils.removeStart;

@FieldDefaults(level = PRIVATE)
final  class TokenAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
  private static final String BEARER = "Bearer";

  @Autowired
  private JWTTokenService tokenService;


  TokenAuthenticationFilter(RequestMatcher rm) {
    super();
     setRequiresAuthenticationRequestMatcher(rm);
//     setFilterProcessesUrl("/api/services/controller/user/login");
   }

  @Override
  public Authentication attemptAuthentication(
    final HttpServletRequest request,
    final HttpServletResponse response) {
    final String param = ofNullable(request.getHeader(AUTHORIZATION))
      .orElse(request.getParameter("t"));

//    final String token = ofNullable(param)
//      .map(value -> removeStart(value, BEARER))
//      .map(String::trim)
//      .orElseThrow(() -> new BadCredentialsException("Missing Authentication Token"));
    User creds =null;
    try {
      creds = new ObjectMapper()
              .readValue(request.getInputStream(), User.class);

      return getAuthenticationManager().authenticate(
              new UsernamePasswordAuthenticationToken(
                      creds.getUsername(),
                      creds.getPassword(),
                      new ArrayList<>())
      );
    }
      catch(Exception e){
        throw new RuntimeException(e);
      }


  }

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
    super.doFilter(req, res, chain);
  }

  @Override
  protected void successfulAuthentication(
    final HttpServletRequest request,
    final HttpServletResponse response,
    final FilterChain chain,
    final Authentication authResult) throws IOException, ServletException {
    super.successfulAuthentication(request, response, chain, authResult);
    //pre validation/autherization
//    chain.doFilter(request, response);
    //post autherization

//    https://www.freecodecamp.org/news/how-to-setup-jwt-authorization-and-authentication-in-spring/


    super.successfulAuthentication(request,response,chain,authResult);

    Cookie cookie = new Cookie("Authorization", URLEncoder.encode(tokenService.permanent(new HashMap<>()), "UTF-8"));
    cookie.setMaxAge(60);	//sets expiration after one minute
    cookie.setSecure(true);
    cookie.setHttpOnly(true);
    cookie.setPath("/vault");

    response.addCookie(cookie);

    response.getWriter().write("ok");
    response.getWriter().flush();

  }
}