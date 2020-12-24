package com.octoperf.security.config;

import lombok.experimental.FieldDefaults;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
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

import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static java.util.Optional.ofNullable;
import static lombok.AccessLevel.PRIVATE;
import static org.apache.commons.lang3.StringUtils.removeStart;

@FieldDefaults(level = PRIVATE, makeFinal = true)
final  class TokenAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
  private static final String BEARER = "Bearer";

   TokenAuthenticationFilter(final RequestMatcher requiresAuth) {
    super();
     setRequiresAuthenticationRequestMatcher(requiresAuth);
  }

  @Override
  public Authentication attemptAuthentication(
    final HttpServletRequest request,
    final HttpServletResponse response) {
    final String param = ofNullable(request.getHeader(AUTHORIZATION))
      .orElse(request.getParameter("t"));

    final String token = ofNullable(param)
      .map(value -> removeStart(value, BEARER))
      .map(String::trim)
      .orElseThrow(() -> new BadCredentialsException("Missing Authentication Token"));

    final Authentication auth = new UsernamePasswordAuthenticationToken(token, token);
    return getAuthenticationManager().authenticate(auth);
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
    chain.doFilter(request, response);
    //post autherization

//    https://www.freecodecamp.org/news/how-to-setup-jwt-authorization-and-authentication-in-spring/


    Cookie cookie = new Cookie("Authorization", "Bearer ");
    cookie.setMaxAge(60);	//sets expiration after one minute
    cookie.setSecure(true);
    cookie.setHttpOnly(true);
    cookie.setPath("/vault");


  }
}