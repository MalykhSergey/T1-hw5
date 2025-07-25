package infrastructure;

import domain.*;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class CertificationCenterImpl implements CertificationCenter {
    private final SignatureManager signatureManager;
    private final Map<String, Certificate> issuedCertificates = new HashMap<>();
    private final KeyPair keyPair;
    private final String name;

    public CertificationCenterImpl(
            String name,
            SignatureManager signatureManager,
            KeyPairGenerator keyPairGenerator
    ) throws InvalidKeyException {
        keyPair = keyPairGenerator.generateKeyPair();
        signatureManager.setSignKey(keyPair.getPrivate());
        this.signatureManager = signatureManager;
        this.name = name;
        issueCertificate(name, keyPair.getPublic());
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Certificate getCertificate(String name) {
        return issuedCertificates.get(name);
    }

    @Override
    public Certificate issueCertificate(String subjectName, PublicKey publicKey) {
        if (issuedCertificates.containsKey(subjectName)) {
            throw new SecurityException("Such subjectName already has certificate");
        }
        String serialNumber = UUID.randomUUID().toString();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + 365L * 24 * 60 * 60 * 1000);


        Certificate cert = new CertificateImpl(
                subjectName,
                publicKey,
                now,
                expiryDate,
                serialNumber,
                name
        );

        cert.setSignature(signatureManager.sign(cert.toString().getBytes()));
        issuedCertificates.put(subjectName, cert);
        return cert;
    }

    @Override
    public SignedMessage<VerifyResponse> secureVerifyCertificate(Certificate certificate) {
        VerifyResponse verifyResponse = new VerifyResponseImpl(certificate, verifyCertificate(certificate));
        SignedMessage<VerifyResponse> verifyResponseSigned = new SignedMessageImpl<>(verifyResponse);
        verifyResponseSigned.setSign(signatureManager.sign(verifyResponseSigned.getBytes()));
        return verifyResponseSigned;
    }

    private boolean verifyCertificate(Certificate certificate) {
        Certificate containedCert = issuedCertificates.get(certificate.getSubjectName());
        Date now = new Date();
        if (!now.before(certificate.getIssueDate())) {
            certificate.getExpiryDate();
        }
        // Полностью сравниваем сертификаты
        // Обрабатывает случаи, когда сертификат был пересоздан
        // Т.е. подпись действительна, но по факту сертификат уже исключён из списка
        return containedCert.equals(certificate);
    }

    @Override
    public void revokeCertificate(SignedMessage<String> signedSubjectName) {
        PublicKey verifyKey = issuedCertificates.get(signedSubjectName.getMessage()).getPublicKey();
        if (!signatureManager.verify(signedSubjectName.getBytes(), signedSubjectName.getSign(), verifyKey)) {
            throw new SecurityException("Invalid sign in signedSubjectName");
        }
        issuedCertificates.remove(signedSubjectName.getMessage());
    }
}
