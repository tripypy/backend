package com.ssafy.jjtrip.common.config;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.util.CollectionUtils;

@Profile("!dev")
@Configuration
@EnableConfigurationProperties(SshTunnelingProperties.class)
public class SshTunnelingInitializer {

    private static final Logger LOGGER = LoggerFactory.getLogger(SshTunnelingInitializer.class);

    private Session session;
    private final SshTunnelingProperties properties;

    public SshTunnelingInitializer(SshTunnelingProperties properties) {
        this.properties = properties;
        if (properties.getHost() == null || properties.getUsername() == null || properties.getPrivateKeyPath() == null || CollectionUtils.isEmpty(properties.getForwardings())) {
            LOGGER.warn("SSH tunneling properties are not set or no forwardings configured. Skipping tunnel setup.");
            return;
        }
        try {
            setupSshTunnel();
        } catch (Exception e) {
            LOGGER.error("Failed to setup SSH tunnel", e);
            throw new RuntimeException(e);
        }
    }

    private void setupSshTunnel() throws Exception {
        JSch jsch = new JSch();
        
        jsch.addIdentity(properties.getPrivateKeyPath());
        LOGGER.info("SSH private key loaded from: {}", properties.getPrivateKeyPath());

        session = jsch.getSession(properties.getUsername(), properties.getHost(), properties.getPort());
        session.setConfig("StrictHostKeyChecking", "no");
        
        LOGGER.info("Connecting to SSH server: {}@{}:{}", properties.getUsername(), properties.getHost(), properties.getPort());
        session.connect();
        LOGGER.info("SSH connection established.");

        for (SshTunnelingProperties.Forwarding forwarding : properties.getForwardings()) {
            int localPort = forwarding.getLocalPort();
            String remoteHost = forwarding.getRemoteHost();
            int remotePort = forwarding.getRemotePort();
            session.setPortForwardingL(localPort, remoteHost, remotePort);
            LOGGER.info("SSH tunnel established: localhost:{} -> {}:{}", localPort, remoteHost, remotePort);
        }
    }

    @PreDestroy
    public void shutdown() {
        if (session != null && session.isConnected()) {
            LOGGER.info("Closing SSH connection.");
            session.disconnect();
        }
    }
}
