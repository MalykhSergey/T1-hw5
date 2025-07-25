package domain;

public interface SignedMessage<T> {
    byte[] getBytes();

    T getMessage();

    byte[] getSign();

    void setSign(byte[] sign);
}
