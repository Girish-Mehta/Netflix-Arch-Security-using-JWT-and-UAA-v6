package com.demo.uaa.uaaserver;

import org.springframework.cloud.netflix.ribbon.RibbonClient;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(value="registration-service",url="localhost:9000")
@RibbonClient(name="registration-service")
public interface UserInformationProxy {

	@PostMapping("/login")
	public String getUserInformationn(@RequestBody UserInformation userInfoInBody);
}