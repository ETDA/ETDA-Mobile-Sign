package th.teda.xmlsigner;

//import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

import th.teda.xmlsigner.configurations.Configurations;

import java.util.Properties;

@SpringBootApplication
public class XmlSignerApplication extends SpringBootServletInitializer {

	@Override
	protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
		return application.sources(XmlSignerApplication.class).properties(getProperties());
	}

	public static void main(String[] args) {
		new SpringApplicationBuilder(XmlSignerApplication.class)
				.sources(XmlSignerApplication.class)
				.properties(getProperties())
				.run(args);
	}

	static Properties getProperties() {
		Properties props = new Properties();
		props.put("spring.config.location", Configurations.configPath);
		return props;
	}

}
