package com.secure.service;

import java.util.HashMap;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.secure.dto.JwtAuthenticationResponce;
import com.secure.dto.RefreshTokenRequest;
import com.secure.dto.SignInRequest;
import com.secure.dto.SignUpRequest;
import com.secure.model.Role;
import com.secure.model.User;
import com.secure.repository.UserRepository;
import com.secure.security.JwtServiceImpl;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
	
	private final UserRepository repo;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager ;
	private final JwtServiceImpl jwtServiceImpl;

	@Override
	public User signUp(SignUpRequest signUpRequest) {
		User user=new User();
		user.setEmail(signUpRequest.getEmail());
		user.setPassword(passwordEncoder.encode( signUpRequest.getPassword()));
		user.setRole(Role.USER);
		return repo.save(user);
	}

	@Override
	public JwtAuthenticationResponce login(SignInRequest signInRequest) {
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signInRequest.getEmail(),signInRequest.getPassword()));
		
		
		var user=repo.findByEmail(signInRequest.getEmail()).orElseThrow(()->new IllegalArgumentException("invalid email id!!"));
		var token = jwtServiceImpl.generateToken(user);
		var refreshToken = jwtServiceImpl.generateRefreshToken(new HashMap<>(),user);
		
		JwtAuthenticationResponce jwtAuthenticationResponce=new JwtAuthenticationResponce();
		jwtAuthenticationResponce.setToken(token);
		jwtAuthenticationResponce.setRefreshToken(refreshToken);
		
		return jwtAuthenticationResponce;
	}

	@Override
	public User adminSignUp(SignUpRequest signUpRequest) {
		User user=new User();
		user.setEmail(signUpRequest.getEmail());
		user.setPassword(passwordEncoder.encode( signUpRequest.getPassword()));
		user.setRole(Role.ADMIN);
		return repo.save(user);
	}

	@Override
	public JwtAuthenticationResponce refreshTokenCreate(RefreshTokenRequest refreshTokenRequest) {
		String userEmail = jwtServiceImpl.extractUserName(refreshTokenRequest.getRefreshToken());
		User dbuser = repo.findByEmail(userEmail).orElseThrow(()->new UsernameNotFoundException("user not found in database!!"));
		if (jwtServiceImpl.isTokenValid(refreshTokenRequest.getRefreshToken(), dbuser)) {
			String token = jwtServiceImpl.generateToken(dbuser);
			
			JwtAuthenticationResponce authenticationResponce=new JwtAuthenticationResponce();
			authenticationResponce.setToken(token);
			authenticationResponce.setRefreshToken(refreshTokenRequest.getRefreshToken());
			return authenticationResponce;
		}
		
		return null;
		
	}


}
