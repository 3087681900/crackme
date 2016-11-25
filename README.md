# crackme

#####一个算法题，使用的都是openssl的标准算法

#####加了点小坑

#####注：build.gradle文件里可以把以下语句删掉，原本是依赖openssl编译，移植过来就不需要这些依赖了

            * platformVersion = 19
            * ldFlags.add("-lcrypto")
            * abiFilters.add("armeabi")
