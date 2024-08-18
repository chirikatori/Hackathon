package com.dqnt.backend.controller;

import com.dqnt.backend.Request.LoginRequest;
import com.dqnt.backend.Request.RegisterRequest;
import com.dqnt.backend.Response.LoginResponse;
import com.dqnt.backend.Response.RegisterResponse;
import com.dqnt.backend.jwt.JwtTokenProvider;
import com.dqnt.backend.model.User;
import com.dqnt.backend.service.AuthService;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    @Autowired
    AuthService authService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @PostMapping("/api/register")
    public RegisterResponse register(@RequestBody RegisterRequest registerRequest) {
        ModelMapper modelMapper = new ModelMapper();
        User user = modelMapper.map(registerRequest, User.class);
        authService.registerUser(user);
        return new RegisterResponse("Register Successfully", true);
    }

    @PostMapping("/api/login")
    public LoginResponse login(@RequestBody LoginRequest loginRequest) {
        try {
            log.info("Start login ...");
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );
            log.info("1");
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("2");
            // Lấy id và username trong request
            String token = jwtTokenProvider.createToken(authentication.getName());
            log.info("3");
            return new LoginResponse(token, "Login Successfully",true);
        } catch (Exception e) {
            return new LoginResponse("", "Invalid username or password", false);
        }
    }

}


