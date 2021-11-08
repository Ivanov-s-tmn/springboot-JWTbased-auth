package com.jm.project.schooljournal.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jm.project.schooljournal.config.jwt.JwtUtils;
import com.jm.project.schooljournal.model.User;
import com.jm.project.schooljournal.repository.UserRepository;
import com.jm.project.schooljournal.security.jwt.JwtProperties;
import com.jm.project.schooljournal.security.request.SignInRequest;
import com.jm.project.schooljournal.security.response.RefreshTokenResponse;
import com.jm.project.schooljournal.security.response.SignInResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;

    public AuthController(UserRepository userRepository,
                          AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signIn(@RequestBody SignInRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                ));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        User user = (User) authentication.getPrincipal();
        String accessToken = JwtUtils.generateToken(user);
        String refreshToken = JwtUtils.generateRefreshToken(user);
        List<String> roles = user.getAuthorities().stream()
                .map(role -> role.getAuthority().substring(5))
                .collect(Collectors.toList());
        return ResponseEntity.ok(new SignInResponse(
                user.getUsername(), roles, accessToken, refreshToken
        ));
    }

    @GetMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request) {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION)
                .replace(JwtProperties.TOKEN_PREFIX, "");
        if (!token.isEmpty()) {
            String username = JwtUtils.getUsernameFromToken(token);
            if (username != null) {
                User userDetails = userRepository.findUserByUsername(username);
                String newAccessToken = JwtUtils.generateToken(userDetails);
                return ResponseEntity.ok(new RefreshTokenResponse(newAccessToken));
            }
            return ResponseEntity.badRequest().body(HttpServletResponse.SC_FORBIDDEN);
        }
        return ResponseEntity.badRequest().body(HttpServletResponse.SC_BAD_REQUEST);
    }
}
