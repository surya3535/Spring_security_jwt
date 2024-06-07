package com.secure.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.secure.model.Role;
import com.secure.service.MyUserDetailsService;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
	
	private final JwtAuthenticationFilter jwtAuthenticationFilter;
	
	private final MyUserDetailsService myUserDetailsService;

	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		return http
				.csrf(AbstractHttpConfigurer::disable)
				.authorizeHttpRequests(auth->
				auth.requestMatchers("api/v1/auth/**").permitAll()
				.requestMatchers("api/v1/admin/**").hasAnyAuthority(Role.ADMIN.name())
				.requestMatchers("api/v1/user/**").hasAnyAuthority(Role.USER.name(),Role.ADMIN.name())
				.anyRequest().authenticated())
				.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authenticationProvider(authenticationProvider())
				.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class).build();
	}
	
	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider dao=new DaoAuthenticationProvider();
		dao.setUserDetailsService(myUserDetailsService);
		dao.setPasswordEncoder(passwordEncoder());
		return dao;
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
		
	}

}
