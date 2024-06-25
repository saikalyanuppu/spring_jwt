package com.example.jwt.service;

import java.util.List;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.jwt.entity.AuthenticationResponse;
import com.example.jwt.entity.Token;
import com.example.jwt.entity.User;
import com.example.jwt.repository.TokenRepository;
import com.example.jwt.repository.UserRepository;

@Service
public class AuthenticationService {

	private final UserRepository repository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;

	private final TokenRepository tokenRepository;

	private final AuthenticationManager authenticationManager;

	public AuthenticationService(UserRepository repository, PasswordEncoder passwordEncoder, JwtService jwtService,
			TokenRepository tokenRepository, AuthenticationManager authenticationManager) {
		this.repository = repository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.tokenRepository = tokenRepository;
		this.authenticationManager = authenticationManager;
	}

	public AuthenticationResponse register(User request) {

		if (repository.findByUsername(request.getUsername()).isPresent()) {
			return new AuthenticationResponse(null, "User already exist");
		}

		User user = new User();
		user.setFirstName(request.getFirstName());
		user.setLastName(request.getLastName());
		user.setUsername(request.getUsername());
		user.setPassword(passwordEncoder.encode(request.getPassword()));
		user.setRole(request.getRole());

		user = repository.save(user);

		String accessToken = jwtService.generateAccessToken(user);

		saveUserToken(accessToken, user);

		return new AuthenticationResponse(accessToken, "User registration was successful");

	}

	public AuthenticationResponse authenticate(User request) {
		authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

		User user = repository.findByUsername(request.getUsername()).orElseThrow();
		String accessToken = jwtService.generateAccessToken(user);

		revokeAllTokenByUser(user);
		saveUserToken(accessToken, user);

		return new AuthenticationResponse(accessToken, "User login was successful");

	}

	private void revokeAllTokenByUser(User user) {
		List<Token> validTokens = tokenRepository.findAllAccessTokensByUser(user.getId());
		if (validTokens.isEmpty()) {
			return;
		}

		validTokens.forEach(t -> {
			t.setLoggedOut(true);
		});

		tokenRepository.saveAll(validTokens);
	}

	private void saveUserToken(String accessToken, User user) {
		Token token = new Token();
		token.setAccessToken(accessToken);
		token.setLoggedOut(false);
		token.setUser(user);
		tokenRepository.save(token);
	}

}