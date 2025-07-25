package infrastructure;

import domain.Certificate;

import java.security.PublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;

public class CertificateImpl implements Certificate {
    private final String subjectName;
    private final PublicKey publicKey;
    private final Date issueDate;
    private final Date expiryDate;
    private final String serialNumber;
    private byte[] signature;
    private final String issuerName;

    public CertificateImpl(String subjectName, PublicKey publicKey, Date issueDate,
                           Date expiryDate, String serialNumber, String issuerName) {
        this.subjectName = subjectName;
        this.publicKey = publicKey;
        this.issueDate = issueDate;
        this.expiryDate = expiryDate;
        this.serialNumber = serialNumber;
        this.issuerName = issuerName;
    }

    @Override
    public String getSubjectName() {
        return subjectName;
    }

    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public Date getIssueDate() {
        return new Date(issueDate.getTime());
    }

    @Override
    public Date getExpiryDate() {
        return new Date(expiryDate.getTime());
    }

    @Override
    public byte[] getSignature() {
        return signature.clone();
    }

    @Override
    public String getIssuerName() {
        return issuerName;
    }

    @Override
    public String toString() {
        return "Certificate{" +
                "subjectName='" + subjectName + '\'' +
                ", issueDate=" + issueDate +
                ", expiryDate=" + expiryDate +
                ", serialNumber='" + serialNumber + '\'' +
                ", issuerName='" + issuerName + '\'' +
                '}';
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        CertificateImpl that = (CertificateImpl) o;
        return Objects.equals(subjectName, that.subjectName) && Objects.equals(publicKey, that.publicKey) && Objects.equals(issueDate, that.issueDate) && Objects.equals(expiryDate, that.expiryDate) && Objects.equals(serialNumber, that.serialNumber) && Objects.deepEquals(signature, that.signature) && Objects.equals(issuerName, that.issuerName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subjectName, publicKey, issueDate, expiryDate, serialNumber, Arrays.hashCode(signature), issuerName);
    }
}
