package com.melardev.spring.websecjwt0.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.melardev.spring.websecjwt0.entities.User;
import com.melardev.spring.websecjwt0.services.UserService;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;


public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private ApplicationContext applicationContext;
    private String jwtSecret;
    private UserService userService;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, ApplicationContext applicationContext) {
        super(authenticationManager);
        this.applicationContext = applicationContext;
        this.jwtSecret = this.applicationContext.getEnvironment().getProperty("app.security.jwt.secret");
        userService = this.applicationContext.getBean(UserService.class);
    }


    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        String header = req.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            SecurityContextHolder.getContext().setAuthentication(null);
            chain.doFilter(req, res);
            return;
        }

        UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        if (token != null) {
            try {
                // parse the token.
                String username = JWT.require(Algorithm.HMAC512(jwtSecret.getBytes()))
                        .build()
                        .verify(token.replace("Bearer ", ""))
                        .getSubject();

                if (username != null) {
                    Optional<User> user = userService.findByUsername(username);
                    if (user.isPresent())
                        return new UsernamePasswordAuthenticationToken(user.get(), null, user.get().getAuthorities());
                }
                return null;
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
        return null;
    }
}
