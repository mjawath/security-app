package com.octoperf.security.config;

import com.octoperf.token.api.TokenService;
import com.octoperf.token.jwt.JWTTokenService;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.octoperf.security.config.SecurityConstants.HEADER_STRING;
import static com.octoperf.security.config.SecurityConstants.TOKEN_PREFIX;

/**
 * Created by jawa on 12/20/2020.
 */
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {


    @NonNull
    TokenService tokens;

    private static final String BEARER = "Bearer";

    @Autowired
    private JWTTokenService tokenService;


    public JWTAuthorizationFilter(AuthenticationManager authManager) {
        super(authManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        String header = req.getHeader(HEADER_STRING);

        if (header == null || !header.startsWith(TOKEN_PREFIX)) {
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    // Reads the JWT from the Authorization header, and then uses JWT to validate the token
    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(HEADER_STRING);
        if (token != null) {
            Authentication auth = tokenService.getAuth(token);
            if (auth != null)
                return (UsernamePasswordAuthenticationToken) auth;
            return null;
        }

        return null;
    }
}