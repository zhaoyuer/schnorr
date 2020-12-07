package com.yuzhao;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

/**
 * @Desc
 * @Author Yu Zhao
 * @Date 2020/12/7 15:32
 * @Version 1.0
 */

@RunWith(PowerMockRunner.class)
@PrepareForTest(Schnorr.class)
public class SchnorrTest {
    @Test
    public void  verify(){
        PowerMockito.mockStatic(Schnorr.class);
        PowerMockito.when(Schnorr.test()).thenReturn(true);
    }
}