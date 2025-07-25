package infrastructure;

import domain.SignedMessage;

public class SignedMessageImpl<T> implements SignedMessage<T> {
    private final T message;
    private byte[] sign;

    public SignedMessageImpl(T message) {
        this.message = message;
    }

    @Override
    public byte[] getBytes() {
        return this.toString().getBytes();
    }

    @Override
    public T getMessage() {
        return message;
    }

    @Override
    public byte[] getSign() {
        return sign;
    }

    @Override
    public void setSign(byte[] sign) {
        this.sign = sign;
    }

    @Override
    public String toString() {
        return "SignedResponseImpl{" +
                "response=" + message + '}';
    }
}
