package io.springsecurity.springsecurity6x.security.statemachine.config;

import com.esotericsoftware.kryo.Kryo;
import com.esotericsoftware.kryo.Serializer;
import com.esotericsoftware.kryo.io.Input;
import com.esotericsoftware.kryo.io.Output;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public class AtomicIntegerSerializer extends Serializer<AtomicInteger> {
    @Override
    public void write(Kryo kryo, Output output, AtomicInteger value) {
        kryo.writeClassAndObject(output, value.get()); // 내부 값만 직렬화
    }

    @Override
    public AtomicInteger read(Kryo kryo, Input input, Class<? extends AtomicInteger> type) {
        int value = (int)kryo.readClassAndObject(input); // 내부 값 역직렬화
        return new AtomicInteger(value);
    }
}