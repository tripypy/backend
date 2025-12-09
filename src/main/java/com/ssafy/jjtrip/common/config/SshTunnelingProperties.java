package com.ssafy.jjtrip.common.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "ssh.tunnel")
public class SshTunnelingProperties {

    private String host;
    private int port;
    private String username;
    private String privateKeyPath;
    private int localPort;
    private String remoteHost;
    private int remotePort;
}
