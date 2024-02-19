package com.example.SpringSecurityJWTAuthentication.jwtConfig;


import com.example.SpringSecurityJWTAuthentication.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Objects;
import java.util.function.Function;

@Service

public class JwtService {

    @Value("${application.security.jwt.key}")
    private  String secretKey;

    @Value("${application.security.jwt.expiration}")
    private  Long expiration;

    public String generateToken(User user){
        HashMap<String,Object>claims=new HashMap<>();
        claims.put("firstName",user.getFirstName());
        claims.put("lastName",user.getLastName());
        return Jwts.builder()
                .claims(claims)
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()+expiration))
                .signWith(signinKey(secretKey))
                .compact();
    }

    public Key signinKey(String secretKey){
        byte[]keyBytes= Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean validateToken(User user,String jwt){
        String username=extractUsername(jwt);
        return username.equals(user.getUsername());
    }

    public Claims extractClaims(String jwt){
        return Jwts.parser()
                .setSigningKey(signinKey(secretKey))
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }

    public <T> T extractClaim(String jwt, Function<Claims,T> claimResolver){
        Claims claims=extractClaims(jwt);
        return claimResolver.apply(claims);
    }

    public String extractUsername(String jwt){
        return extractClaim(jwt,Claims::getSubject);
    }
}
