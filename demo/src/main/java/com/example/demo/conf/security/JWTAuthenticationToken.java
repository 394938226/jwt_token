package com.example.demo.conf.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import static java.util.Collections.emptyList;

public class JWTAuthenticationToken extends UsernamePasswordAuthenticationToken {

    public JWTAuthenticationToken(Object principal) {
        super(principal,null,emptyList());
    }

    @Override
    public Object getCredentials() {
        return super.getCredentials();
    }

    @Override
    public Object getPrincipal() {
        return super.getPrincipal();
    }
}
