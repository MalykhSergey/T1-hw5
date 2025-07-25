package infrastructure;

import domain.SignatureManager;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class SignatureManagerImpl implements SignatureManager {
    private final Signature signSignature;
    private final Signature verifySignature;

    SignatureManagerImpl(String alg, AlgorithmParameterSpec parameterSpec) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        this.signSignature = Signature.getInstance(alg);
        this.verifySignature = Signature.getInstance(alg);
        signSignature.setParameter(parameterSpec);
        verifySignature.setParameter(parameterSpec);
    }

    @Override
    public byte[] sign(byte[] data) {
        try {
            signSignature.update(data);
            return signSignature.sign();
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean verify(byte[] data, byte[] sign, PublicKey verifyKey) {
        try {
            verifySignature.initVerify(verifyKey);
            verifySignature.update(data);
            return verifySignature.verify(sign);
        } catch (SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void setSignKey(PrivateKey privateKey) {
        try {
            signSignature.initSign(privateKey);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}
