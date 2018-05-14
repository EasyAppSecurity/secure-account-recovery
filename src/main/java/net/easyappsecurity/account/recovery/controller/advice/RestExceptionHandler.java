package net.easyappsecurity.account.recovery.controller.advice;

import net.easyappsecurity.account.recovery.validation.ErrorDetails;
import net.easyappsecurity.account.recovery.validation.ErrorField;
import net.easyappsecurity.account.recovery.validation.ErrorType;
import net.easyappsecurity.account.recovery.validation.RestException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.Collection;
import java.util.Date;

@ControllerAdvice
@RestController
public class RestExceptionHandler extends ResponseEntityExceptionHandler {

    @Autowired
    private MessageSource messages;

    @ExceptionHandler(RestException.class)
    public final ResponseEntity<ErrorDetails> handleRestException(RestException ex, WebRequest request) {
        Collection<ErrorField> errors = ex.getErrors();
        ErrorDetails errorDetails = new ErrorDetails(new Date(), errors, request.getDescription(false));
        return new ResponseEntity<>(errorDetails, HttpStatus.NOT_ACCEPTABLE);
    }

    @ExceptionHandler({UsernameNotFoundException.class})
    public ResponseEntity<ErrorDetails> handleUserNotFound(RuntimeException ex, WebRequest request) {
        String message = messages.getMessage("message.userNotFound", null, request.getLocale());
        ErrorDetails errorDetails = new ErrorDetails(new Date(),
                new ErrorField("user", ErrorType.USER_NOT_FOUND, message),
                request.getDescription(false)
        );
        return new ResponseEntity<>(errorDetails, HttpStatus.NOT_FOUND);
    }

}
