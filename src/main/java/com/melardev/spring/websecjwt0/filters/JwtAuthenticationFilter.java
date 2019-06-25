package com.melardev.spring.websecjwt0.filters;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.melardev.spring.websecjwt0.dtos.requests.LoginDto;
import com.melardev.spring.websecjwt0.dtos.responses.ErrorResponse;
import com.melardev.spring.websecjwt0.dtos.responses.LoginSuccessResponse;
import com.melardev.spring.websecjwt0.entities.User;
import com.melardev.spring.websecjwt0.services.UserService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter implements InitializingBean {


    private final ApplicationContext applicationContext;
    private AuthenticationManager authenticationManager;
    private ObjectMapper objectMapper;
    private UserService userService;


    public JwtAuthenticationFilter(ApplicationContext applicationContext) {
        super();
        setFilterProcessesUrl("/api/auth/login");
        this.applicationContext = applicationContext;
    }

    @Value("${app.security.jwt.expiration_seconds}")
    private long expirationTimeInSeconds;
    private final String TOKEN_PREFIX = "Bearer ";

    @Value("${app.security.jwt.secret}")
    private String jwtSecret;


    @Override
    public void afterPropertiesSet() {
        this.objectMapper = this.applicationContext.getBean(ObjectMapper.class);
        this.authenticationManager = this.applicationContext.getBean(AuthenticationManager.class);
        this.userService = this.applicationContext.getBean(UserService.class);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req,
                                                HttpServletResponse res) throws AuthenticationException {
        try {
            LoginDto loginDto = objectMapper
                    .readValue(req.getInputStream(), LoginDto.class);

            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginDto.getUsername(),
                            loginDto.getPassword(),
                            Collections.emptyList())
            );

        } catch (IOException e) {
            throw new RuntimeException("Failed to Read the Request");
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {

        GrantedAuthority[] roles = new GrantedAuthority[auth.getAuthorities().size()];
        auth.getAuthorities().toArray(roles);

        String[] rolesArray = Arrays.stream(roles).map(GrantedAuthority::getAuthority).collect(Collectors.toList()).toArray(new String[roles.length]);

        String token = JWT.create()
                .withSubject(((User) auth.getPrincipal()).getUsername())
                .withArrayClaim("roles", rolesArray)
                .withExpiresAt(new Date(System.currentTimeMillis() + 1000 * expirationTimeInSeconds))
                .sign(Algorithm.HMAC512(jwtSecret.getBytes()));
        // res.addHeader(HttpHeaders.AUTHORIZATION, TOKEN_PREFIX + token);
        res.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        res.getWriter().write(objectMapper.writeValueAsString(LoginSuccessResponse.build(token, (User) auth.getPrincipal())));

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(new ErrorResponse("Invalid Credentials")));
    }
}