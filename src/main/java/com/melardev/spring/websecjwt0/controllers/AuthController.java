package com.melardev.spring.websecjwt0.controllers;


import com.melardev.spring.websecjwt0.dtos.responses.AppResponse;
import com.melardev.spring.websecjwt0.dtos.responses.ErrorResponse;
import com.melardev.spring.websecjwt0.dtos.responses.SuccessResponse;
import com.melardev.spring.websecjwt0.entities.User;
import com.melardev.spring.websecjwt0.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
public class AuthController {

    @Autowired
    UserService userService;

    // @Autowired AuthenticationManager authenticationManager;

    @PostMapping("/api/users")
    public ResponseEntity<AppResponse> registerUser(@Valid @RequestBody User user, BindingResult result) {

        if (userService.findByUsername(user.getUsername()).isPresent()) {
            return new ResponseEntity<>(new ErrorResponse("Username already taken"), HttpStatus.BAD_REQUEST);
        }
        userService.createUser(user.getUsername(), user.getPassword());
        return new ResponseEntity<>(new SuccessResponse("User registered successfully"), HttpStatus.OK);
    }


    /*
    @PostMapping("/api/auth/login") // This is implemented on the JwtAuthenticationFilter
    public ResponseEntity<AppResponse> login(@Valid @RequestBody LoginDto loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtProvider.generateJwtToken(authentication);
        User user = (User) authentication.getPrincipal();

        return ResponseEntity.ok(LoginSuccessResponse.build(jwt, user));
    }
    */
}
