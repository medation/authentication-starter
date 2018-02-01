package com.devit.service;

import com.devit.model.User;

public interface IUserService {
	
	void save(User user);
	User findByUsernameOrEmail(String usermaneOrEmail);
	User findById(int id);
	boolean UserNameOrEmailExists(String usernameOrEmail);
	
}
