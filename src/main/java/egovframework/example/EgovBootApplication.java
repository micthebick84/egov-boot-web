package egovframework.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan("egovframework.example.config")
public class EgovBootApplication {

	public static void main(String[] args) {
		SpringApplication.run(EgovBootApplication.class, args);
	}

}
