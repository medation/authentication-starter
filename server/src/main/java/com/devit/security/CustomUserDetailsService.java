package com.devit.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.devit.model.Role;
import com.devit.model.User;
import com.devit.service.IUserService;
import com.devit.service.implement.UserService;

@Service("customUserDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private IUserService userService;

	@Override
	@Transactional(readOnly = true)
	public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {

		if (usernameOrEmail.trim().isEmpty()) {
			throw new UsernameNotFoundException("username is empty");
		}

		User user = userService.findByUsernameOrEmail(usernameOrEmail);

		if (user == null) {
			throw new UsernameNotFoundException("User " + usernameOrEmail + " not found");
		}

		return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
				getGrantedAuthorities(user));
	}

	private List<GrantedAuthority> getGrantedAuthorities(User user) {
		
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		Role role = user.getRole();
		authorities.add(new SimpleGrantedAuthority(role.getRole()));
		return authorities;
		
	}

}

