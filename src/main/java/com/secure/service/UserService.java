package com.secure.service;

import com.secure.dto.JwtAuthenticationResponce;
import com.secure.dto.RefreshTokenRequest;
import com.secure.dto.SignInRequest;
import com.secure.dto.SignUpRequest;
import com.secure.model.User;

public interface UserService {
	
	User signUp(SignUpRequest signUpRequest);

	JwtAuthenticationResponce login(SignInRequest signInRequest);

	User adminSignUp(SignUpRequest signUpRequest);

	JwtAuthenticationResponce refreshTokenCreate(RefreshTokenRequest refreshTokenRequest);


}
