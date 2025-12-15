package com.ssafy.jjtrip.common.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@Getter
@Setter
@ConfigurationProperties(prefix = "ssh.tunnel")
public class SshTunnelingProperties {

    private String host;
    private int port;
    private String username;
    private String privateKeyPath;
    private List<Forwarding> forwardings;

    @Getter
    @Setter
    public static class Forwarding {
        private int localPort;
        private String remoteHost;
        private int remotePort;
    }
}
