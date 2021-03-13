package com.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class UserService implements UserDetailsService {
	
//	@Autowired
//	UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		// Logic to get the user form the Database

		return new User("Admin", "password", new ArrayList<>());
	}
	
	/*
	 * @Override
	 * 
	 * @Transactional public UserDetails loadUserByUsername(String username) throws
	 * UsernameNotFoundException { User user =
	 * userRepository.findByUsername(username) .orElseThrow(() -> new
	 * UsernameNotFoundException("User Not Found with username: " + username));
	 * 
	 * return UserDetailsImpl.build(user); }
	 */
}
