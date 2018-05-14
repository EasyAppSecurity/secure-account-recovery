package net.easyappsecurity.account.recovery.validation;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

public class ErrorDetails implements Serializable {

    private Date timestamp;
    private Collection<ErrorField> errors;
    private String details;

    public ErrorDetails(Date timestamp, Collection<ErrorField> errors, String details) {
        this.timestamp = timestamp;
        this.errors = errors;
        this.details = details;
    }

    public ErrorDetails(Date timestamp, ErrorField error, String details) {
        this.timestamp = timestamp;
        this.errors = new ArrayList<>(1);
        this.errors.add(error);
        this.details = details;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    public Collection<ErrorField> getErrors() {
        return errors;
    }

    public void setErrors(Collection<ErrorField> errors) {
        this.errors = errors;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }
}
