package com.main.controller;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.main.modal.UserInformation;
import com.main.service.UserRegistrationService;

@RestController
public class RegistrationController {

	@Autowired
	UserRegistrationService userService;
	
	@PostMapping("/register")
	// adding validation using @valid
	public ResponseEntity<Object> addUserInformation(@Valid @RequestBody UserInformation dataOfUserInBody) {
		userService.addUserInformation(dataOfUserInBody);
		// this is added to give a response that the uri that is going to be created is
		// successfully created
		URI location = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}")
				.buildAndExpand(dataOfUserInBody.getUserId()).toUri();
		return ResponseEntity.created(location).build();
	}

	@GetMapping("/register")
	public List<UserInformation> getAllRegisteredUserInformation() {
		return userService.getAllRegisteredUserInformation();
	}

	@GetMapping("/register/{id}")
	public Optional<UserInformation> getUserInformation(@PathVariable String id) {
		return userService.getUserInformation(id);
	}

	@PostMapping("/login")
	public String getUserInformationn(@RequestBody UserInformation userInfoInBody) {
		String message = "";
		String getPassword = "";
		UserInformation info = null;
		Optional<UserInformation> retrieverIformation = userService.getUserInformation(userInfoInBody.getUserId());

		if (!retrieverIformation.isPresent()) {
			message = "Not Found";
		} else {
			info = retrieverIformation.get();
			getPassword = info.getPassword();
			if (getPassword.equals(userInfoInBody.getPassword())) {
				message = userInfoInBody.getUserId()+","+info.getRole();

			} else {
				message = "Invalid";
			}
		}

		return message;
	}
}
