package com.melardev.spring.websecjwt0.config;


import com.melardev.spring.websecjwt0.filters.JwtAuthenticationFilter;
import com.melardev.spring.websecjwt0.filters.JwtAuthorizationFilter;
import com.melardev.spring.websecjwt0.security.AuthEntryPoint;
import com.melardev.spring.websecjwt0.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    @Value("${spring.h2.console.enabled:false}")
    private boolean h2ConsoleEnabled;

    @Autowired
    UserService userDetailsService;

    @Autowired
    private JwtAuthenticationFilter authenticationFilter;

    @Autowired
    AuthEntryPoint authEntryPoint;

    public WebSecurityConfig() {

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.debug(true);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        if (h2ConsoleEnabled) {
            http.authorizeRequests()
                    .antMatchers("/h2-console", "/h2-console/**").permitAll()
                    .and()
                    .headers().frameOptions().sameOrigin();
        }
        http.cors().and().csrf().disable().authorizeRequests()
                .antMatchers(HttpMethod.POST, "/api/users").permitAll()
                .antMatchers(HttpMethod.GET, "/api/todos**").permitAll()
                .antMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
                .anyRequest().authenticated()
                .and()
                // Authentication first then Authorization
                .addFilter(authenticationFilter)
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), getApplicationContext()))
                .exceptionHandling().authenticationEntryPoint(authEntryPoint)
                .and()
                // this disables session creation on Spring Security
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
}
