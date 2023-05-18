# CowInject

1. Close KPTI;Supprot win10 20h1 win7 sp1;support 2M 1G Page
2. Dll start in first export function
3. Compile release vs2019 x64
4. Blog: https://blog.csdn.net/qq_37353105/article/details/123253770
5. When you stop driver the target process maybe be crash
6. it just a demo

心血来潮的修改：

1.修正了一个bug，清零pde和pte的G位，如果不清零会导致切换线程的时候tlb未及时刷新，访问申请的内核地址出现0xC0000005的情况（还有就是添加和去除User位以及G位都是偷懒的写法，可能有问题）

懒人不想修改的地方

1.其实不关闭kpti也能玩，因为r3用的是UserDirectoryTableBase，所以需要修改的是这里指向的物理地址，r0的线性地址是没有映射的，可以手动添加，在用windbg调试的时候就算你是.process /i xxxx进程获取的cr3也是r0的，要看r3的用!dq自己按照9 9 9 9 12拆分一下就行了。

2.有部分代码写的有问题，就是在attachprocess的dpc level下ProbeForRead/Write加上__try是handle不了的，所以在attachprocess的时候进来还是用MmIsAddressValid，虽然MmIsAddressValid也只是检查了一下页属性，但这不就够了吗？

