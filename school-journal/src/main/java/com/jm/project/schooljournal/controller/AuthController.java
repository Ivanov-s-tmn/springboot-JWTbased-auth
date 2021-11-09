package com.jm.project.schooljournal.controller;

import com.jm.project.schooljournal.security.request.LogOutRequest;
import com.jm.project.schooljournal.security.request.LoginRequest;
import com.jm.project.schooljournal.security.request.RefreshTokenRequest;
import com.jm.project.schooljournal.security.response.AuthenticationResponse;
import com.jm.project.schooljournal.service.AuthService;
import com.jm.project.schooljournal.service.RefreshTokenService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(AuthService authService, RefreshTokenService refreshTokenService) {
        this.authService = authService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh/token")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@Valid @RequestBody LogOutRequest request) {
        return ResponseEntity.ok(authService.logout(request));
    }
}
