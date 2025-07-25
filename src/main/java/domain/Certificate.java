package domain;

import java.security.PublicKey;
import java.util.Date;

public interface Certificate {
    String getSubjectName();
    PublicKey getPublicKey();
    Date getIssueDate();
    Date getExpiryDate();
    byte[] getSignature();
    void setSignature(byte[] signature);
    String getIssuerName();
}
