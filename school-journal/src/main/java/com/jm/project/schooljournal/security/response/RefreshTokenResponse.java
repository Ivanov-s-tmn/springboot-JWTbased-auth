package com.jm.project.schooljournal.security.response;

public class RefreshTokenResponse {

    private String accessToken;

    public RefreshTokenResponse(String newAccessToken) {
        this.accessToken = newAccessToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }
}
