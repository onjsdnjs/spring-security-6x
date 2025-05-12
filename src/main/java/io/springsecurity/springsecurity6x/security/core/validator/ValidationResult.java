package io.springsecurity.springsecurity6x.security.core.validator;

import java.util.ArrayList;
import java.util.List;

public class ValidationResult {
    private final List<String> errors = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();

    public void addError(String err)   { errors.add(err); }
    public void addWarning(String w)   { warnings.add(w); }
    public boolean hasErrors()         { return !errors.isEmpty(); }
    public boolean hasCritical()       { return hasErrors(); }
    public List<String> getErrors()    { return errors; }
    public List<String> getWarnings()  { return warnings; }

    public String toJson() {
        return String.format("{\"errors\":%s,\"warnings\":%s}",
                errors.toString(), warnings.toString());
    }
}

