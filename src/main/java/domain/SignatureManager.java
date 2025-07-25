package domain;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface SignatureManager {
    byte[] sign(byte[] data);

    boolean verify(byte[] data, byte[] sign, PublicKey verifyKey);

    void setSignKey(PrivateKey privateKey);
}
