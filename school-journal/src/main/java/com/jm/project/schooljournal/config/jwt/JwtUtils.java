package com.jm.project.schooljournal.config.jwt;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.jm.project.schooljournal.model.User;
import com.jm.project.schooljournal.security.jwt.JwtProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {

    public static String getUsernameFromToken(String token) {
        return JWT.require(Algorithm.HMAC512(JwtProperties.SECRET.getBytes()))
                .build()
                .verify(token)
                .getSubject();
    }

    public static String generateToken(User user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() +
                        JwtProperties.ACCESS_TOKEN_EXPIRATION))
                .sign(Algorithm.HMAC512(JwtProperties.SECRET.getBytes()));
    }

    public static String generateRefreshToken(User user) {
         return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() +
                        JwtProperties.REFRESH_TOKEN_EXPIRATION))
                .sign(Algorithm.HMAC512(JwtProperties.SECRET.getBytes()));
    }
}
