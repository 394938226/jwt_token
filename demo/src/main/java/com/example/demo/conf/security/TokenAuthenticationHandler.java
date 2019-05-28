package com.example.demo.conf.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class TokenAuthenticationHandler {

    private static final String CLAIM_KEY_CREATED = "created";
    private static final String CLAIM_KEY_SUBJECT = "subject";
    private static final String DEFAULT_SECRET = "@*secret@*";
    //有效期3天
    private static final Long DEFAULT_EXPIRATION = 259200L;

    public TokenAuthenticationHandler() {

    }

    public String getSubjectFromToken(String token) {
        String subject;
        try {
            final Claims claims = getClaimsFromToken(token);
            subject = claims.get(CLAIM_KEY_SUBJECT).toString();
        } catch (Exception e) {
            subject = null;
        }
        return subject;
    }

    private Claims getClaimsFromToken(String token) {
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(DEFAULT_SECRET).parseClaimsJws(token).getBody();
        } catch (Exception e) {
            claims = null;
        }
        return claims;
    }

    private Date generateExpirationDate() {
        return new Date(System.currentTimeMillis() + DEFAULT_EXPIRATION * 1000);
    }

    public String generateToken(String subject) {
        Map<String, Object> claims = new HashMap<String, Object>();
        claims.put(CLAIM_KEY_CREATED, new Date());
        claims.put(CLAIM_KEY_SUBJECT, subject);
        return generateToken(claims);
    }

    public String generateToken(Map<String, Object> claims) {
        return Jwts.builder().setClaims(claims).setExpiration(generateExpirationDate())
                .signWith(SignatureAlgorithm.HS512, DEFAULT_SECRET).compact();
    }
}
