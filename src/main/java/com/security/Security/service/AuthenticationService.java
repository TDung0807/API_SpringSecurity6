package com.security.Security.service;

import com.security.Security.dto.JwtAuthenticationResponse;
import com.security.Security.dto.RefreshTokenRequest;
import com.security.Security.dto.SignInRequest;
import com.security.Security.dto.SignUpRequest;
import com.security.Security.entity.User;

public interface AuthenticationService {
    User signup(SignUpRequest signUpRequest);
    JwtAuthenticationResponse signin(SignInRequest signInRequest);
    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
