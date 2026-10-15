package com.chen.miniwsa;

import org.springframework.boot.SpringApplication;

public class TestMiniWsaApplication {

	public static void main(String[] args) {
		SpringApplication.from(MiniWsaApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}
