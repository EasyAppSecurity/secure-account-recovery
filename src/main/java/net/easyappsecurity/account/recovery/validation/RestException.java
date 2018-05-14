package net.easyappsecurity.account.recovery.validation;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

public class RestException extends RuntimeException {

    private Collection<ErrorField> errors = Collections.EMPTY_LIST;

    public RestException(Collection<ErrorField> errors) {
        this.errors = errors;
    }

    public RestException(ErrorField error) {
        super(error.getMessage());
        this.errors = new ArrayList<>(1);
        this.errors.add(error);
    }

    public RestException(String field, ErrorType code, String message) {
        super(message);
        this.errors = new ArrayList<>(1);
        this.errors.add(new ErrorField(field, code, message));
    }

    public Collection<ErrorField> getErrors() {
        return errors;
    }
}
