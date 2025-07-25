package infrastructure;

import domain.CertificationCenter;
import domain.CryptoFactory;
import domain.SignatureManager;
import domain.User;

import javax.crypto.KeyGenerator;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class CryptoFactoryImpl implements CryptoFactory {

    public static final String SIGN_ALG = "RSASSA-PSS";
    public static final String KEY_GEN_ALG = "AES";
    public static final String ASYMMETRIC_ALG = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String SYMMETRIC_ALG = "AES/CBC/PKCS5Padding";
    private final CertificationCenterImpl certificationCenter;

    public CryptoFactoryImpl() {
        try {
            certificationCenter = new CertificationCenterImpl("GlobalCertificationCenter=SimpleCA", createSignatureManager(), createKeyPairGenerator());
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public SignatureManager createSignatureManager() {
        AlgorithmParameterSpec algorithmParameterSpec = new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
        );
        try {
            return new SignatureManagerImpl(SIGN_ALG, algorithmParameterSpec);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public User createUser(String name) {
        return new CryptoUser(name, certificationCenter, createKeyPairGenerator(), createSignatureManager(), SIGN_ALG, KEY_GEN_ALG, ASYMMETRIC_ALG, SYMMETRIC_ALG);
    }

    @Override
    public KeyPairGenerator createKeyPairGenerator() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public KeyGenerator createKeyGenerator() {
        try {
            return KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public CertificationCenter getCertificationCenter() {
        return certificationCenter;
    }
}
