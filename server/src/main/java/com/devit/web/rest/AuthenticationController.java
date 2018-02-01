package com.devit.web.rest;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.devit.model.Role;
import com.devit.model.User;
import com.devit.repository.RoleRepository;
import com.devit.security.jwt.TokenProvider;
import com.devit.service.IUserService;
import com.devit.service.implement.UserService;

@RestController
@CrossOrigin
public class AuthenticationController {

	@Autowired
	private IUserService userService;

	@Autowired
	private RoleRepository roleRepository;
	
	private final TokenProvider tokenProvider;

	private final PasswordEncoder passwordEncoder;
    
	private final AuthenticationManager authenticationManager;

	public AuthenticationController(PasswordEncoder passwordEncoder, TokenProvider tokenProvider, AuthenticationManager authenticationManager) {

		this.tokenProvider = tokenProvider;
		this.passwordEncoder = passwordEncoder;
		this.authenticationManager = authenticationManager;

	}

	@GetMapping("/authenticate")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void authenticate() {

	}

	@PostMapping("/login")
	public String authorize(@Valid @RequestBody User user, HttpServletResponse response) {
		
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

		try {
			this.authenticationManager.authenticate(authenticationToken);
			return this.tokenProvider.createToken(user.getUsername());
		}
		catch (AuthenticationException e) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return null;
		}
		
	}

	@PostMapping("/registre")
	public String registre(@RequestBody User user) {
		
		if (this.userService.UserNameOrEmailExists(user.getUsername())) {
			return "EXISTS";
		}
		user.setRole(roleRepository.findOne(1));
		user.encodePassword(this.passwordEncoder);
	    this.userService.save(user);
	    return this.tokenProvider.createToken(user.getUsername());
		
	}
	
	@GetMapping("/loadRole")
	public void loadRole() {
		Role user = new Role(1,"USER");
		Role admin = new Role(2,"ADMIN");
		roleRepository.save(user);
		roleRepository.save(admin);
	}

}

