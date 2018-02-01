package com.devit.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.devit.security.jwt.JwtConfigurer;
import com.devit.security.jwt.TokenProvider;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	private final TokenProvider tokenProvider;

	@Autowired
	@Qualifier("customUserDetailsService")
	private UserDetailsService customUserDetailsService;
	
	public WebSecurityConfig(TokenProvider tokenProvider) {
		this.tokenProvider = tokenProvider;
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
	    // @formatter:off
			http
			  .csrf()
			    .disable()
			  .cors()
			    .and()
			  .sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
			//.httpBasic() // optional, if you want to access 
			//  .and()     // the services from a browser
			  .authorizeRequests()
			    .antMatchers("/registre").permitAll()
			    .antMatchers("/login").permitAll()
			    .antMatchers("/public").permitAll()
			    .antMatchers("/loadRole").permitAll()
			    .anyRequest().authenticated()
			    .and()
			  .apply(new JwtConfigurer(this.tokenProvider));
			// @formatter:on
	}

}
