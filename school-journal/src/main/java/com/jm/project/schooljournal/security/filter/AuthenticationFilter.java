package com.jm.project.schooljournal.security.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jm.project.schooljournal.config.jwt.JwtUtils;
import com.jm.project.schooljournal.model.User;
import com.jm.project.schooljournal.security.jwt.JwtProperties;
import com.jm.project.schooljournal.security.request.SignInRequest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

//public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {
//
//    private final AuthenticationManager authenticationManager;
//
//    public AuthenticationFilter(AuthenticationManager authenticationManager) {
//        this.authenticationManager = authenticationManager;
//        setFilterProcessesUrl("/auth/signin");
//    }
//
//    @Override
//    public Authentication attemptAuthentication(HttpServletRequest request,
//                                                HttpServletResponse response)
//            throws AuthenticationException {
//        SignInRequest credentials = null;
//        try {
//            credentials = new ObjectMapper()
//                    .readValue(request.getInputStream(), SignInRequest.class);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//        UsernamePasswordAuthenticationToken authenticationToken =
//                new UsernamePasswordAuthenticationToken(
//                        credentials.getUsername(),
//                        credentials.getPassword(),
//                        new ArrayList<>());
//        return authenticationManager.authenticate(authenticationToken);
//    }
//
//    @Override
//    protected void successfulAuthentication(HttpServletRequest request,
//                                            HttpServletResponse response,
//                                            FilterChain chain,
//                                            Authentication auth)
//            throws IOException, ServletException {
//        User user = (User) auth.getPrincipal();
//        String accessToken = JwtUtils.generateToken(user);
//        String refreshToken = JWT.create()
//                .withSubject(user.getUsername())
//                .withExpiresAt(new Date(System.currentTimeMillis() +
//                        JwtProperties.REFRESH_TOKEN_EXPIRATION))
//                .sign(Algorithm.HMAC512(JwtProperties.SECRET.getBytes()));
//        List<GrantedAuthority> authorities = new ArrayList<>(user.getAuthorities());
//        Map<String, String> principals = new HashMap<>();
//        principals.put("username", user.getUsername());
//        for (GrantedAuthority authority : authorities) {
//            principals.put("authority", authority.getAuthority());
//        }
//        principals.put("accessToken", accessToken);
//        principals.put("refreshToken", refreshToken);
//        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//        new ObjectMapper().writeValue(response.getOutputStream(), principals);
//    }
//}
