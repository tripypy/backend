package com.ssafy.jjtrip;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableAsync;

@EnableAsync
@SpringBootApplication
@ComponentScan(basePackages = "com.ssafy.jjtrip")
public class JjtripApplication {

	public static void main(String[] args) {
		SpringApplication.run(JjtripApplication.class, args);
	}

}
