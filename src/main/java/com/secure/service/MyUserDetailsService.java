package com.secure.service;

import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.secure.model.User;
import com.secure.repository.UserRepository;

import lombok.RequiredArgsConstructor;


@Service
@RequiredArgsConstructor
public class MyUserDetailsService implements UserDetailsService {
	
	private final UserRepository repo;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return repo.findByEmail(username).orElseThrow(()-> new UsernameNotFoundException("User not found !!!!"));
		
	}

}
