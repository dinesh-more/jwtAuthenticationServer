package com.jwt.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class HomeController {

	@GetMapping("/")
	public String home() {
		return "JWT-Server";
	}

	@RequestMapping(value = "/user")
	public String getUser() {
		return "{\"name\":\"Dinesh\"}";
	}
}
