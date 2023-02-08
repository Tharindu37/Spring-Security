package com.developerstack.security.jwt_config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    /*@Value("{$secretKey}")*/
    private String secretKey="tjjlafjjoejqfjlkajfjlsjflssjajeorjfolksjfoeirjfjlkfajslkkjlajflkjfslkfjlkjouru4uugueroiifjoiwhroiifjlkjlsgjfsljlksjglkfkjlkjfkdjk";

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            UsernameAndPasswordRequest usernameAndPasswordRequest=new ObjectMapper()
                    .readValue(request.getInputStream(),UsernameAndPasswordRequest.class);
            Authentication authentication=new UsernamePasswordAuthenticationToken(
                    usernameAndPasswordRequest.getUsername(),
                    usernameAndPasswordRequest.getPassword()
            );
            return authenticationManager.authenticate(authentication);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        /*String key=;*/
        String token= Jwts.builder()
                .setSubject(authResult.getName())
                        .claim("authorities",authResult.getAuthorities())
                                .setIssuedAt(new Date())
                                        .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusDays(31)))
                                                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
                                                        .compact();
        response.addHeader("Authorization","Bearer "+token);
    }
}
