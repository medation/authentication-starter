package com.devit.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.devit.model.User;

@Repository("userRepository")
public interface UserRepository extends JpaRepository<User, Integer>{

	@Query("SELECT u FROM User u WHERE u.username=:usernameOrEmail OR u.email=:usernameOrEmail")
	User findByUsernameOrEmail(@Param("usernameOrEmail")String usernameOrEmail);
	User findByEmail(String email);
	
}
