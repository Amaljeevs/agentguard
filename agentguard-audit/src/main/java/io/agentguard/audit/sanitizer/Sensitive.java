package io.agentguard.audit.sanitizer;

import java.lang.annotation.*;

/** Masks a record component or public bean getter without reading its value. */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.RECORD_COMPONENT, ElementType.METHOD})
public @interface Sensitive {}
