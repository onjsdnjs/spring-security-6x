package io.springsecurity.springsecurity6x.security.core.asep.handler.model;

import org.springframework.util.Assert;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class HandlerMethod {

    private final Object bean;
    private final Method method;
    private final Class<? extends Throwable>[] exceptionTypes;
    private final int priority;
    private final List<String> produces;

    public HandlerMethod(Object bean, Method method, Class<? extends Throwable>[] exceptionTypes, int priority, String[] produces) {
        Assert.notNull(bean, "Bean is required");
        Assert.notNull(method, "Method is required");

        this.bean = bean;
        this.method = method;
        this.exceptionTypes = (exceptionTypes != null && exceptionTypes.length > 0) ? exceptionTypes : inferExceptionTypes(method);
        this.priority = priority;
        this.produces = (produces != null && produces.length > 0) ? Arrays.asList(produces) : Collections.emptyList();
    }

    @SuppressWarnings("unchecked")
    private Class<? extends Throwable>[] inferExceptionTypes(Method method) {
        for (Class<?> paramType : method.getParameterTypes()) {
            if (Throwable.class.isAssignableFrom(paramType)) {
                return new Class[]{ (Class<? extends Throwable>) paramType };
            }
        }
        return new Class[]{ Throwable.class };
    }

    public Object getBean() { return bean; }
    public Method getMethod() { return method; }
    public Class<? extends Throwable>[] getExceptionTypes() { return exceptionTypes; }
    public int getPriority() { return priority; }
    public List<String> getProduces() { return produces; }

    public boolean canHandle(Class<? extends Throwable> exceptionType) {
        for (Class<? extends Throwable> supportedType : this.exceptionTypes) {
            if (supportedType.isAssignableFrom(exceptionType)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String toString() {
        return "HandlerMethod{" +
                "bean=" + bean.getClass().getName() +
                ", method=" + method.getName() +
                ", exceptionTypes=" + Arrays.toString(exceptionTypes) +
                ", priority=" + priority +
                ", produces=" + produces +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        HandlerMethod that = (HandlerMethod) o;
        return priority == that.priority &&
                bean.equals(that.bean) &&
                method.equals(that.method) &&
                Arrays.equals(exceptionTypes, that.exceptionTypes) &&
                produces.equals(that.produces);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(bean, method, priority, produces);
        result = 31 * result + Arrays.hashCode(exceptionTypes);
        return result;
    }
}
