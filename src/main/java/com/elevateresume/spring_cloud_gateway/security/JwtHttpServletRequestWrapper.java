package com.elevateresume.spring_cloud_gateway.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.springframework.http.HttpHeaders;

import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public class JwtHttpServletRequestWrapper extends HttpServletRequestWrapper {

    private final String jwtToken;

    public JwtHttpServletRequestWrapper(HttpServletRequest request, String jwtToken) {
        super(request);
        this.jwtToken = jwtToken;
    }

    @Override
    public String getHeader(String name) {
        if (HttpHeaders.AUTHORIZATION.equalsIgnoreCase(name)) {
            return "Bearer " + jwtToken;
        }
        return super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        if (HttpHeaders.AUTHORIZATION.equalsIgnoreCase(name)) {
            return Collections.enumeration(List.of("Bearer " + jwtToken));
        }
        return super.getHeaders(name);
    }

    // Override getHeaderNames to include "Authorization"
    @Override
    public Enumeration<String> getHeaderNames() {
        List<String> headerNames = Collections.list(super.getHeaderNames());
        headerNames.add(HttpHeaders.AUTHORIZATION);
        return Collections.enumeration(headerNames);
    }
}
