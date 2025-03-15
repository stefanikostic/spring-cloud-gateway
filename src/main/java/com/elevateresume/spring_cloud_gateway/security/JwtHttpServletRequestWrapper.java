package com.elevateresume.spring_cloud_gateway.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.springframework.http.HttpHeaders;

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
}
