package com.secure.security;

import java.security.Key;
import java.util.Date;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.lang.Function;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtServiceImpl {
	

	public String generateToken(UserDetails userDetails){
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30))
                .signWith(getSignInKey(), Jwts.SIG.HS256)
                .compact();
    }
	
	public String generateRefreshToken(Map<String,Object> extractClaims ,UserDetails userDetails){
		return Jwts.builder()
				.claims(extractClaims)
				.subject(userDetails.getUsername())
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30))
				.signWith(getSignInKey(), Jwts.SIG.HS256)
				.compact();
	}

	
	 private SecretKey getSignInKey() {
	        byte[] keyBytes = Decoders.BASE64.decode("8523698521478569874563214587532569854769321458756985647315987582");
	        return Keys.hmacShaKeyFor(keyBytes);
	    }

	 public String extractUserName(String token) {
		 return extractClaims(token,Claims::getSubject);
	 }

	private <T> T extractClaims(String token, Function<Claims, T> claimResolver) {
		final Claims claims=extractAllClaims(token);
		return claimResolver.apply(claims);
	}

	
	private Claims extractAllClaims(String token) {
		return Jwts.parser().verifyWith(getSignInKey()).build().parseSignedClaims(token).getPayload();
	}
	
	public boolean isTokenValid(String token,UserDetails userDetails) {
		final String username=extractUserName(token);
		return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
	}

	private boolean isTokenExpired(String token) {
		return extractClaims(token, Claims::getExpiration).before(new Date());
	}
	
}
