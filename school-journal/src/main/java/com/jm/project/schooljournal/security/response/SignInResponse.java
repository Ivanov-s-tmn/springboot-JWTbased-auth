package com.jm.project.schooljournal.security.response;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

public class SignInResponse {

    private String username;
    private List<String> roles;
    private String accessToken;
    private String refreshToken;

    public SignInResponse(String username, List<String> roles, String accessToken, String refreshToken) {
        this.username = username;
        this.roles = roles;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
