package com.yuzhao;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

/**
 * @Desc
 * @Author Yu Zhao
 * @Date 2020/12/7 13:28
 * @Version 1.0
 */

@RunWith(PowerMockRunner.class)
@PrepareForTest(Sec256K1Ecc.class)
public class Sec256K1EccTest {


    @Test
    public void  verify(){
        PowerMockito.mockStatic(Sec256K1Ecc.class);
        Mockito.when(Sec256K1Ecc.testA()).thenReturn(true);
    }
}