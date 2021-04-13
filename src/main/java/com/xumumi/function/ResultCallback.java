package com.xumumi.function;

/**
 * 结果处理函数接口
 *
 * @author XUMUMI
 * @since 1.9
 * @param <Input> 传入类型
 */
@FunctionalInterface
public interface ResultCallback<Input> {
    /**
     * 执行回调函数
     *
     * @param path   调用路径
     * @param result 执行结果
     * @return 可序列化对象
     */
    Object apply(String path, Input result);
}
