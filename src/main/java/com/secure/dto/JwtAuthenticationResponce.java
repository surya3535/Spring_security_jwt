package com.secure.dto;

import lombok.Data;

@Data
public class JwtAuthenticationResponce {

	private String token;
	private String refreshToken;
}
