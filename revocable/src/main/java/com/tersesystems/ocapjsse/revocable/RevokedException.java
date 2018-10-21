package com.tersesystems.ocapjsse.revocable;

public class RevokedException extends RuntimeException {

  public RevokedException(String message) {
    super(message);
  }

  public RevokedException(String message, Throwable cause) {
    super(message, cause);
  }

  public RevokedException(Throwable cause) {
    super(cause);
  }

  public RevokedException(
      String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}
