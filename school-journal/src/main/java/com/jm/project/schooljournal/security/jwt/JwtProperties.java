package com.jm.project.schooljournal.security.jwt;

public class JwtProperties {

    public static final String SECRET = "schoolPortalSecret";
    public static final Long ACCESS_TOKEN_EXPIRATION = 300_000L;
    public static final Long REFRESH_TOKEN_EXPIRATION = 840_000_000L;
    public static final String TOKEN_PREFIX = "Bearer ";
}
