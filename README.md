# linux-mm-annotation
linux内存管理模块部分代码注释
##内容简介
本工程包含了linux内核4.4版本内存管理mm目录核心代码的中文注释。相关代码注释参考的材料皆来自网上，
因能力所限，无法保证理解的准确性，大部分注释是一边阅读代码，一边拿来主义直接添加在代码中，主要是方便自己的理解。

##一点说明
* 所有代码中包含的中文注释，皆来自于网上各种资料的。
* 内存管理所包含的功能所解决的问题和实现方案，可以参考Documentation目录，或者[LWN](http://lwn.net/Kernel/Index/)

##linux内存管理有哪些功能

* 以下列出的功能包含了linux内核内存管理的大部分功能，有时间的话，会整理出一系列的文章。

###物理内存的管理
* 内存初始化阶段的内存管理(bootmem.c, early_ioremap.c, memblock.c)
* 内核内存的布局(DMA,NORMAL,HIGHMEM,MOVABLE)等
* 基于page的内存分配(page_alloc.c)
 * NUMA多内存节点管理
 * 伙伴buddy分配系统
   *  碎片过多时,两种碎片整理策略：compaction(compaction.c)和reclaim(内存回收机制)
   *  碎片过多时,还可以从已经分配的CMA内存中临时借用分配.
* 基于对象的内存分配缓存(SLAB,SLOB,SLUB)
 * SLAB的对象高速缓存实现
 * 用于内存非常有限系统的SLOB
 * SLAB的替代者SLUB
* 内核高端内存的实现(highmem.c)
* 连续内存分配器(CMA)
 * 预留的大块连续内存,以满足驱动程序需要。
 * 内存碎片过多时，伙伴系统可以临时借用
* 防止碎片的策略
 * 按照不同分配类型的内存分配策略,UNMOVABLE,MOVABLE,PCPTYPES,RECLAIMABLE,ISOLATE等(migrate.c)
 * 基于zone的不同类型内存的分配策略NORMAL,MOVABLE(memory.c)
* DMA内存管理: 与硬件相关的内存访问管理
* 内存热插拔支持(memory_hotplug.c)
* 硬件io与内存映射: 让访问外设如同访问内存一样简单
 * io映射机制(io)
* 内存重复页面的合并(ksm.c)
 * 如何识别重复页面
 * 合并的时机
* 内核对大内存页的特性的支持
 * 基于VFS文件系统的hugetlbfs的实现(hugetlb.c)
 * 三级目录映射的实现机制(huge_memory.c)
* 交换分区(swap.c swapfile.c)
 * 基于VFS的交换分区管理
 * 交换页缓存机制


###进程角度的内存空间管理
* 内存页表(memory.c)
 * 通用四级页表模型及其功能
 * 进程的内存管理
 * 匿名类型的内存映射(mmap.c)
* 匿名页表缓存机制
* 页面回收功能(vmscan.c)
 * linux的增强的LRU算法
 * 匿名和文件类型的active与inactive链表的功能
 * 拆分出被锁页的链表
 * 进程工作集的支持(Workingset.c)
* 页面写回(writeback),与文件系统相关
 * 脏页阈值的作用
 * 回写线程的实现机制与变迁(backing-dev.c, page-writeback.c)
 * 脏页生成和写回
 * 干净页缓存(cleancache.c)
   *  用于缓存那些因长时间未访问而无辜被回收的干净页
   *  采用tmem(transcendent memory)机制对页面进行管理
* transcendent memory实现机制
 * cleancache前端实现
 * frontswap前端实现
* 页面预读, 页表的缓存,与文件系统相关
 * 按需预读
* 文件页表缓存机制(filemap.c)
* 反向映射(rmap.c)

###内存基础设施之上的高级功能
* percpu数据结构，改善内核数据结构的竞争访问(percpu.c)
* memory cgroups的支持(memcontrol.c)
 * 基于cgroups的内存分配限制
 * 基于cgroups的内存回收和交换
 * 内存的cgroups如何影响进程的实际行为
* 内核内存泄漏检查辅助功能(kmemleak.c)
* 内存检测访问非法的内存地址的功能(kmemcheck.c)

