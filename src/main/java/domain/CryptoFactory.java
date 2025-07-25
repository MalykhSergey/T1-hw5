package domain;

import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;

public interface CryptoFactory {
    SignatureManager createSignatureManager();
    User createUser(String name);
    KeyPairGenerator createKeyPairGenerator();
    KeyGenerator createKeyGenerator();
    CertificationCenter getCertificationCenter();
}
