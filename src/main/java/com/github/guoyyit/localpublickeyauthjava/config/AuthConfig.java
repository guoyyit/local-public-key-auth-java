package com.github.guoyyit.localpublickeyauthjava.config;

import com.github.guoyyit.localpublickeyauthjava.crypto.CryptoService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration
@EnableScheduling
@EnableConfigurationProperties(AuthProperties.class)
public class AuthConfig {

    @Bean
    public CryptoService cryptoService() {
        return new CryptoService();
    }
}
