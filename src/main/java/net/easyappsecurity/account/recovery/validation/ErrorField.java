package net.easyappsecurity.account.recovery.validation;

import java.io.Serializable;

public class ErrorField implements Serializable {

    private String field;
    private ErrorType code;
    private String message;

    public ErrorField(String field, ErrorType code, String message) {
        this.field = field;
        this.code = code;
        this.message = message;
    }

    public String getField() {
        return field;
    }

    public void setField(String field) {
        this.field = field;
    }

    public ErrorType getCode() {
        return code;
    }

    public void setCode(ErrorType code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
