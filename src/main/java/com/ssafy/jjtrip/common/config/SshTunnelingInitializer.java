package com.ssafy.jjtrip.common.config;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Profile("!dev")
@Configuration
@EnableConfigurationProperties(SshTunnelingProperties.class)
public class SshTunnelingInitializer {

    private static final Logger LOGGER = LoggerFactory.getLogger(SshTunnelingInitializer.class);

    private Session session;
    private final SshTunnelingProperties properties;

    public SshTunnelingInitializer(SshTunnelingProperties properties) {
        this.properties = properties;
        if (properties.getHost() == null || properties.getUsername() == null || properties.getPrivateKeyPath() == null) {
            LOGGER.warn("SSH tunneling properties are not set. Skipping tunnel setup.");
            return;
        }
        try {
            setupSshTunnel();
        } catch (Exception e) {
            LOGGER.error("Failed to setup SSH tunnel", e);
            // 애플리케이션을 시작하지 않으려면 여기서 예외를 다시 던질 수 있습니다.
            throw new RuntimeException(e);
        }
    }

    private void setupSshTunnel() throws Exception {
        JSch jsch = new JSch();
        
        // private key 설정
        jsch.addIdentity(properties.getPrivateKeyPath());
        LOGGER.info("SSH private key loaded from: {}", properties.getPrivateKeyPath());

        session = jsch.getSession(properties.getUsername(), properties.getHost(), properties.getPort());
        
        // 호스트 키 검사 비활성화 (보안상 주의 필요)
        // 실제 운영 환경에서는 known_hosts 파일을 설정하는 것이 더 안전합니다.
        session.setConfig("StrictHostKeyChecking", "no");
        
        LOGGER.info("Connecting to SSH server: {}@{}:{}", properties.getUsername(), properties.getHost(), properties.getPort());
        session.connect();
        LOGGER.info("SSH connection established.");

        // 로컬 포트 포워딩 설정
        // L: local port, R: remote host, R: remote port
        // 로컬 포트를 원격 서버의 원격 포트로 포워딩합니다.
        int localPort = properties.getLocalPort();
        String remoteHost = properties.getRemoteHost();
        int remotePort = properties.getRemotePort();
        session.setPortForwardingL(localPort, remoteHost, remotePort);
        LOGGER.info("SSH tunnel established: localhost:{} -> {}:{}", localPort, remoteHost, remotePort);
    }

    @PreDestroy
    public void shutdown() {
        if (session != null && session.isConnected()) {
            LOGGER.info("Closing SSH connection.");
            session.disconnect();
        }
    }
}
