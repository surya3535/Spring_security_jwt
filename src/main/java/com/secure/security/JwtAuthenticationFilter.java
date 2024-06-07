package com.secure.security;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.secure.service.MyUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter{
	
	private final JwtServiceImpl jwtServiceImpl;
	private final MyUserDetailsService myUserDetailsService;
	
	
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String authHeader = request.getHeader("Authorization");
		final String jwt;
		final String userEmail;
		
		//check empty and not startwith bearer
		if (ObjectUtils.isEmpty(request) || !StringUtils.startsWithIgnoreCase(authHeader,"Bearer ")) {
			filterChain.doFilter(request,response);
			return;
		}
		jwt=authHeader.substring(7);
		userEmail=jwtServiceImpl.extractUserName(jwt);
		
		//run block when email has length and contextholder does not have any saved token
		if (StringUtils.hasLength(userEmail) && SecurityContextHolder.getContext().getAuthentication() == null){
			//extract user from databse
			UserDetails dbUserDetails = myUserDetailsService.loadUserByUsername(userEmail);
			
			
			//token valid
			if (jwtServiceImpl.isTokenValid(jwt, dbUserDetails)) {
				//create empty securityContext
				SecurityContext securityContext=SecurityContextHolder.createEmptyContext();
				
				UsernamePasswordAuthenticationToken token=new UsernamePasswordAuthenticationToken(dbUserDetails, null, dbUserDetails.getAuthorities());
				token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				
				securityContext.setAuthentication(token);
				SecurityContextHolder.setContext(securityContext);
				
			}
		}
		filterChain.doFilter(request, response);
		
	}

}
