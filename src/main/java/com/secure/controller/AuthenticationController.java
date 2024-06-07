package com.secure.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.secure.dto.JwtAuthenticationResponce;
import com.secure.dto.RefreshTokenRequest;
import com.secure.dto.SignInRequest;
import com.secure.dto.SignUpRequest;
import com.secure.model.User;
import com.secure.security.JwtAuthenticationFilter;
import com.secure.service.UserService;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

	private final UserService service;

	@PostMapping("/signup")
	public ResponseEntity<User> signUp(@RequestBody SignUpRequest signUpRequest) {
		return new ResponseEntity<User>(service.signUp(signUpRequest), HttpStatus.OK);
	}
	
	@PostMapping("/login")
	public ResponseEntity<JwtAuthenticationResponce> login(@RequestBody SignInRequest SignInRequest) {
		return new ResponseEntity<JwtAuthenticationResponce>(service.login(SignInRequest), HttpStatus.OK);
	}
	
	@PostMapping("/admin-signup")
	public ResponseEntity<User> adminSignUp(@RequestBody SignUpRequest signUpRequest) {
		return new ResponseEntity<User>(service.adminSignUp(signUpRequest), HttpStatus.OK);
	}
	
	
	@PostMapping("/refresh")
	public ResponseEntity<JwtAuthenticationResponce> refreshTokenCreate(@RequestBody RefreshTokenRequest refreshTokenRequest) {
		return new ResponseEntity<JwtAuthenticationResponce>(service.refreshTokenCreate(refreshTokenRequest), HttpStatus.OK);
	}
}
