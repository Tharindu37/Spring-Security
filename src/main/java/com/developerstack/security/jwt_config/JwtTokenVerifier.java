package com.developerstack.security.jwt_config;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {
    /*@Value("{$secretKey}")*/
    private String secretKey="tjjlafjjoejqfjlkajfjlsjflssjajeorjfolksjfoeirjfjlkfajslkkjlajflkjfslkfjlkjouru4uugueroiifjoiwhroiifjlkjlsgjfsljlksjglkfkjlkjfkdjk";
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader=request.getHeader("Authorization");
        if (Strings.isNullOrEmpty(authHeader) || authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        try {
            String token=authHeader.replace("Bearer ","");
            Jws<Claims> claimsJws= Jwts.parser()
                    .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes()))
                    .parseClaimsJws(token);
            Claims tokenBody=claimsJws.getBody();
            String username=tokenBody.getSubject();

            var authorities=(List<Map<String,String>>) tokenBody.get("authorities");
            Set<SimpleGrantedAuthority> grantedAuthorities=authorities.stream()
                    .map(data->new SimpleGrantedAuthority(data.get("authority")))
                    .collect(Collectors.toSet());

            Authentication authentication=new UsernamePasswordAuthenticationToken(
                username,null,grantedAuthorities
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }catch (Exception e){
            throw new IllegalStateException("Token was Rejected!");
            /*throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);*/
        }
    }
}
