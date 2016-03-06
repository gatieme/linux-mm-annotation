/*
 * High memory handling common code and variables.
 *
 * (C) 1999 Andrea Arcangeli, SuSE GmbH, andrea@suse.de
 *          Gerhard Wichert, Siemens AG, Gerhard.Wichert@pdb.siemens.de
 *
 *
 * Redesigned the x86 32-bit VM architecture to deal with
 * 64-bit physical space. With current x86 CPUs this
 * means up to 64 Gigabytes physical RAM.
 *
 * Rewrote high memory support to move the page cache into
 * high memory. Implemented permanent (schedulable) kmaps
 * based on Linus' idea.
 *
 * Copyright (C) 1999 Ingo Molnar <mingo@redhat.com>
 */

#include <linux/mm.h>
#include <linux/export.h>
#include <linux/swap.h>
#include <linux/bio.h>
#include <linux/pagemap.h>
#include <linux/mempool.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/highmem.h>
#include <linux/kgdb.h>
#include <asm/tlbflush.h>


#if defined(CONFIG_HIGHMEM) || defined(CONFIG_X86_32)
DEFINE_PER_CPU(int, __kmap_atomic_idx);
#endif

/*
 * Virtual_count is not a pure "count".
 *  0 means that it is not mapped, and has not been mapped
 *    since a TLB flush - it is usable.
 *  1 means that there are no users, but it has been mapped
 *    since the last TLB flush - so we can't use it.
 *  n means that there are (n-1) current users of it.
 */
#ifdef CONFIG_HIGHMEM

/*
 * Architecture with aliasing data cache may define the following family of
 * helper functions in its asm/highmem.h to control cache color of virtual
 * addresses where physical memory pages are mapped by kmap.
 */
#ifndef get_pkmap_color

/*
 * Determine color of virtual address where the page should be mapped.
 */
static inline unsigned int get_pkmap_color(struct page *page)
{
	return 0;
}
#define get_pkmap_color get_pkmap_color

/*
 * Get next index for mapping inside PKMAP region for page with given color.
 */
static inline unsigned int get_next_pkmap_nr(unsigned int color)
{
	static unsigned int last_pkmap_nr;

	last_pkmap_nr = (last_pkmap_nr + 1) & LAST_PKMAP_MASK;
	return last_pkmap_nr;
}

/*
 * Determine if page index inside PKMAP region (pkmap_nr) of given color
 * has wrapped around PKMAP region end. When this happens an attempt to
 * flush all unused PKMAP slots is made.
 */
static inline int no_more_pkmaps(unsigned int pkmap_nr, unsigned int color)
{
	return pkmap_nr == 0;
}

/*
 * Get the number of PKMAP entries of the given color. If no free slot is
 * found after checking that many entries, kmap will sleep waiting for
 * someone to call kunmap and free PKMAP slot.
 */
static inline int get_pkmap_entries_count(unsigned int color)
{
	return LAST_PKMAP;
}

/*
 * Get head of a wait queue for PKMAP entries of the given color.
 * Wait queues for different mapping colors should be independent to avoid
 * unnecessary wakeups caused by freeing of slots of other colors.
 */
static inline wait_queue_head_t *get_pkmap_wait_queue_head(unsigned int color)
{
	static DECLARE_WAIT_QUEUE_HEAD(pkmap_map_wait);

	return &pkmap_map_wait;
}
#endif

unsigned long totalhigh_pages __read_mostly;
EXPORT_SYMBOL(totalhigh_pages);


EXPORT_PER_CPU_SYMBOL(__kmap_atomic_idx);

unsigned int nr_free_highpages (void)
{
	pg_data_t *pgdat;
	unsigned int pages = 0;

	for_each_online_pgdat(pgdat) {
		pages += zone_page_state(&pgdat->node_zones[ZONE_HIGHMEM],
			NR_FREE_PAGES);
		if (zone_movable_is_highmem())
			pages += zone_page_state(
					&pgdat->node_zones[ZONE_MOVABLE],
					NR_FREE_PAGES);
	}

	return pages;
}

/**
 * 该数组的每一个元素对应于一个持久映射的kmap页,表示被映射页的使用计数。
 * 当计数值为2时，表示有一处使用了该页。0表示没有使用。1表示页面已经映射，但是TLB没有更新，因此无法使用。
 *
 * Pkmap_count数组包含LAST_PKMAP个计数器，pkmap_page_table页表中每一项都有一个。
 * 它记录了永久内核映射使用了哪些页表项。它的值可能为：
 *	0：对应的页表项没有映射任何高端内存页框，并且是可用的。
 *	1：对应页表项没有映射任何高端内存，但是它仍然不可用。因为自从它最后一次使用以来，相应的TLB表还没有被刷新。
 *	>1：相应的页表项映射了一个高端内存页框。并且正好有n-1个内核正在使用这个页框。
 */
static int pkmap_count[LAST_PKMAP];
static  __cacheline_aligned_in_smp DEFINE_SPINLOCK(kmap_lock);

/**
 * 用于建立永久内核映射的页表。内核可以长期映射高端内存到内核地址空间中。
 * 页表中的表项数由LAST_PKMAP宏产生，取决于是否打开PAE，
 * 它的值可能是512或者1024，可能映射2MB或4MB的永久内核映射。
 */
pte_t * pkmap_page_table;

/*
 * Most architectures have no use for kmap_high_get(), so let's abstract
 * the disabling of IRQ out of the locking in that case to save on a
 * potential useless overhead.
 */
#ifdef ARCH_NEEDS_KMAP_HIGH_GET
#define lock_kmap()             spin_lock_irq(&kmap_lock)
#define unlock_kmap()           spin_unlock_irq(&kmap_lock)
#define lock_kmap_any(flags)    spin_lock_irqsave(&kmap_lock, flags)
#define unlock_kmap_any(flags)  spin_unlock_irqrestore(&kmap_lock, flags)
#else
#define lock_kmap()             spin_lock(&kmap_lock)
#define unlock_kmap()           spin_unlock(&kmap_lock)
#define lock_kmap_any(flags)    \
		do { spin_lock(&kmap_lock); (void)(flags); } while (0)
#define unlock_kmap_any(flags)  \
		do { spin_unlock(&kmap_lock); (void)(flags); } while (0)
#endif

struct page *kmap_to_page(void *vaddr)
{
	unsigned long addr = (unsigned long)vaddr;

	if (addr >= PKMAP_ADDR(0) && addr < PKMAP_ADDR(LAST_PKMAP)) {
		int i = PKMAP_NR(addr);
		return pte_page(pkmap_page_table[i]);
	}

	return virt_to_page(addr);
}
EXPORT_SYMBOL(kmap_to_page);

static void flush_all_zero_pkmaps(void)
{
	int i;
	int need_flush = 0;

	flush_cache_kmaps();

	for (i = 0; i < LAST_PKMAP; i++) {
		struct page *page;

		/*
		 * zero means we don't have anything to do,
		 * >1 means that it is still in use. Only
		 * a count of 1 means that it is free but
		 * needs to be unmapped
		 */
		if (pkmap_count[i] != 1)
			continue;
		pkmap_count[i] = 0;

		/* sanity check */
		BUG_ON(pte_none(pkmap_page_table[i]));

		/*
		 * Don't need an atomic fetch-and-clear op here;
		 * no-one has the page mapped, and cannot get at
		 * its virtual address (and hence PTE) without first
		 * getting the kmap_lock (which is held here).
		 * So no dangers, even with speculative execution.
		 */
		page = pte_page(pkmap_page_table[i]);
		pte_clear(&init_mm, PKMAP_ADDR(i), &pkmap_page_table[i]);

		set_page_address(page, NULL);
		need_flush = 1;
	}
	if (need_flush)
		flush_tlb_kernel_range(PKMAP_ADDR(0), PKMAP_ADDR(LAST_PKMAP));
}

/**
 * kmap_flush_unused - flush all unused kmap mappings in order to remove stray mappings
 */
void kmap_flush_unused(void)
{
	lock_kmap();
	flush_all_zero_pkmaps();
	unlock_kmap();
}

/**
 * 为建立永久内核映射建立初始映射.
 */
static inline unsigned long map_new_virtual(struct page *page)
{
	unsigned long vaddr;
	int count;
	unsigned int last_pkmap_nr;
	unsigned int color = get_pkmap_color(page);

start:
	/* 最多循环遍历一次pkmap_count数组 */
	count = get_pkmap_entries_count(color);
	/* Find an empty entry */
	/**
	 * 扫描pkmap_count中的所有计数器值,直到找到一个空值.
	 */
	for (;;) {
		/* 从上一次查找的位置开始查找空闲虚拟地址 */
		last_pkmap_nr = get_next_pkmap_nr(color);
		/**
		 * 搜索到最后一位了.在从0开始搜索前,刷新计数为1的项.
		 * 当计数值为1表示页表项可用,但是对应的TLB还没有刷新.
		 */
		if (no_more_pkmaps(last_pkmap_nr, color)) {
			/* 将所有计数为1的地址，清除其pte映射，刷新tlb。延迟刷新tlb，因为刷新tlb是耗时的操作 */
			flush_all_zero_pkmaps();
			count = get_pkmap_entries_count(color);
		}
		/* 找到可用地址 */
		/**
		 * 找到计数为0的页表项,表示该页空闲且可用.
		 */
		if (!pkmap_count[last_pkmap_nr])
			break;	/* Found a usable entry */
		/**
		 * count是允许的搜索次数.如果还允许继续搜索下一个页表项.则继续,否则表示没有空闲项,退出.
		 */
		if (--count)
			continue;

		/*
		 * Sleep for somebody else to unmap their entries
		 */
		/* 运行到这里，说明没有可用虚拟地址，必须等待其他地方调用kunmap释放虚拟地址 */
		/**
		 * 运行到这里,表示没有找到空闲页表项.先睡眠一下.
		 * 等待其他线程释放页表项,然后唤醒本线程.
		 */
		{
			DECLARE_WAITQUEUE(wait, current);
			wait_queue_head_t *pkmap_map_wait =
				get_pkmap_wait_queue_head(color);

			/* 将自己挂到pkmap_map_wait等待队列 */
			__set_current_state(TASK_UNINTERRUPTIBLE);
			/**
			 * 将当前线程挂到pkmap_map_wait等待队列上.
			 */
			add_wait_queue(pkmap_map_wait, &wait);
			/* 释放全局锁并睡眠。该锁由调用者获取 */
			unlock_kmap();
			schedule();
			/* 其他地方调用了kunmap，重新获取全局锁并重试 */
			remove_wait_queue(pkmap_map_wait, &wait);
			lock_kmap();

			/* Somebody else might have mapped it while we slept */
			/* 在睡眠的过程中，其他地方可能已经重新映射了该页，直接访问即可 */
			/**
			 * 在当前线程等待的过程中,其他线程可能已经将页面进行了映射.
			 * 检测一下,如果已经映射了,就退出.
			 * 注意,这里没有对kmap_lock进行解锁操作.关于kmap_lock锁的操作,需要结合kmap_high来分析.
			 * 总的原则是:进入本函数时保证关锁,然后在本句前面关锁,本句后面解锁.
			 * 在函数返回后,锁仍然是关的.则外层解锁.即使在本函数中循环也是这样.
			 * 内核就是这么乱,看久了就习惯了.不过你目前可能必须得学着适应这种代码.
			 */
			if (page_address(page))
				return (unsigned long)page_address(page);

			/* Re-start */
			/* 重新查找可用虚拟地址 */
			goto start;
		}
	}
	/* 计算获得的虚拟地址 */
	/**
	 * 不管何种路径运行到这里来,kmap_lock都是锁着的.
	 * 并且last_pkmap_nr对应的是一个空闲且可用的表项.
	 */
	vaddr = PKMAP_ADDR(last_pkmap_nr);
	/* 修改pte映射项 */
	/**
	 * 设置页表属性,建立虚拟地址和物理地址之间的映射.
	 */
	set_pte_at(&init_mm, vaddr,
		   &(pkmap_page_table[last_pkmap_nr]), mk_pte(page, kmap_prot));

	/* 这里将使用计数初始化为1，调用者会再增加计数为2，表示有一个使用计数 */
	/**
	 * 1表示相应的项可用,但是TLB需要刷新.
	 * 但是我们这里明明建立了映射,为什么还是可用的呢,其他地方不会将占用么
	 * 其实不用担心,因为返回kmap_high后,kmap_high函数会将它再加1.
	 */
	pkmap_count[last_pkmap_nr] = 1;
	set_page_address(page, (void *)vaddr);

	return vaddr;
}

/**
 * kmap_high - map a highmem page into memory
 * @page: &struct page to map
 *
 * Returns the page's virtual memory address.
 *
 * We cannot call this from interrupts, as it may block.
 */
/**
 * 将高端内存映射到虚拟地址
 */
void *kmap_high(struct page *page)
{
	unsigned long vaddr;

	/*
	 * For highmem pages, we can't trust "virtual" until
	 * after we have the lock.
	 */
	/* 这里必须获得这个全局锁，才能确信page_address是正确的 */
	lock_kmap();
	/**
	 * page_address有检查页框是否被映射的作用。
	 */
	vaddr = (unsigned long)page_address(page);
	/**
	 * 没有被映射，就调用map_new_virtual把页框的物理地址插入到pkmap_page_table的一个项中。
	 * 并在page_address_htable散列表中加入一个元素。
	 */
	/* 还没映射到高端地址 */
	if (!vaddr)
		/* 获得虚拟地址并映射到页面，注意这里会释放锁，并阻塞，因此本函数不能在中断中调用 */
		vaddr = map_new_virtual(page);
	/* 增加虚拟地址使用计数，在map_new_virtual中设置了初始值为1，此时应该为2或者更大的值 */
	/**
	 * 使页框的线性地址所对应的计数器加1.
	 */
	pkmap_count[PKMAP_NR(vaddr)]++;
	/**
	 * 初次映射时,map_new_virtual中会将计数置为1,上一句再加1.
	 * 多次映射时,计数值会再加1.
	 * 总之,计数值决不会小于2.
	 */
	BUG_ON(pkmap_count[PKMAP_NR(vaddr)] < 2);
	/* 释放全局锁，并返回地址 */
	unlock_kmap();
	return (void*) vaddr;
}

EXPORT_SYMBOL(kmap_high);

#ifdef ARCH_NEEDS_KMAP_HIGH_GET
/**
 * kmap_high_get - pin a highmem page into memory
 * @page: &struct page to pin
 *
 * Returns the page's current virtual memory address, or NULL if no mapping
 * exists.  If and only if a non null address is returned then a
 * matching call to kunmap_high() is necessary.
 *
 * This can be called from any context.
 */
void *kmap_high_get(struct page *page)
{
	unsigned long vaddr, flags;

	lock_kmap_any(flags);
	vaddr = (unsigned long)page_address(page);
	if (vaddr) {
		BUG_ON(pkmap_count[PKMAP_NR(vaddr)] < 1);
		pkmap_count[PKMAP_NR(vaddr)]++;
	}
	unlock_kmap_any(flags);
	return (void*) vaddr;
}
#endif

/**
 * kunmap_high - unmap a highmem page into memory
 * @page: &struct page to unmap
 *
 * If ARCH_NEEDS_KMAP_HIGH_GET is not defined then this may be called
 * only from user context.
 */
/**
 * 解除高端内存的永久内核映射
 */
void kunmap_high(struct page *page)
{
	unsigned long vaddr;
	unsigned long nr;
	unsigned long flags;
	int need_wakeup;
	unsigned int color = get_pkmap_color(page);
	wait_queue_head_t *pkmap_map_wait;

	/* 获取全局kmap锁 */
	lock_kmap_any(flags);
	/* 查找页面的虚拟地址 */
	/**
	 * 得到物理页对应的虚拟地址。
	 */
	vaddr = (unsigned long)page_address(page);
	/**
	 * vaddr会==0，可能是内存越界等严重故障了吧。BUG一下
	 * 如果页面没有被映射过，说明调用者遇到异常情况 
	 */
	BUG_ON(!vaddr);
	/**
	 * 根据虚拟地址，找到页表项在pkmap_count中的序号。
	 * 计算该地址在kmap虚拟空间中的索引
	 */
	nr = PKMAP_NR(vaddr);

	/*
	 * A count must never go down to zero
	 * without a TLB flush!
	 */
	need_wakeup = 0;
	/* 递减虚拟地址引用计数 */
	switch (--pkmap_count[nr]) {
	case 0:
	/* 永远不可能为0，为1才表示没有映射 */
		BUG();
	case 1:
	/* 完全解除映射了 */
		/*
		 * Avoid an unnecessary wake_up() function call.
		 * The common case is pkmap_count[] == 1, but
		 * no waiters.
		 * The tasks queued in the wait-queue are guarded
		 * by both the lock in the wait-queue-head and by
		 * the kmap_lock.  As the kmap_lock is held here,
		 * no need for the wait-queue-head's lock.  Simply
		 * test if the queue is empty.
		 */
		/* 如果有等待虚拟地址的进程，则需要唤醒 */
		pkmap_map_wait = get_pkmap_wait_queue_head(color);
		/**
		 * 页表项可用了。need_wakeup会唤醒等待队列上阻塞的线程。
		 */
		need_wakeup = waitqueue_active(pkmap_map_wait);
	}
	/* 释放全局锁 */
	unlock_kmap_any(flags);

	/* do wake-up, if needed, race-free outside of the spin lock */
	/**
	 * 有等待线程，唤醒它。释放锁以后再唤醒，避免长时间获得锁
	 */
	if (need_wakeup)
		wake_up(pkmap_map_wait);
}

EXPORT_SYMBOL(kunmap_high);
#endif

#if defined(HASHED_PAGE_VIRTUAL)

#define PA_HASH_ORDER	7

/*
 * Describes one page->virtual association
 */
/**
 * 描述物理内存页与虚拟地址之间的关联
 */
struct page_address_map {
	/* 页面对象 */
	struct page *page;
	/* 映射的虚拟地址 */
	void *virtual;
	/* 通过此字段链接到哈希表page_address_htable的桶中 */
	struct list_head list;
};

static struct page_address_map page_address_maps[LAST_PKMAP];

/*
 * Hash table bucket
 */
/**
 * page_address_htable哈希表，用于防止虚拟地址冲突, 其散列函数是page_slot
 * 本散列表记录了高端内存页框与永久内核映射映射包含的线性地址。
 */
static struct page_address_slot {
	struct list_head lh;			/* List of page_address_maps */
	spinlock_t lock;			/* Protect this bucket's list */
} ____cacheline_aligned_in_smp page_address_htable[1<<PA_HASH_ORDER];

static struct page_address_slot *page_slot(const struct page *page)
{
	return &page_address_htable[hash_ptr(page, PA_HASH_ORDER)];
}

/**
 * page_address - get the mapped virtual address of a page
 * @page: &struct page to get the virtual address of
 *
 * Returns the page's virtual address.
 */
/**
 * 确定某个物理页面的虚拟地址。
 * 可能在page_address_htable哈希表中查找
 */
void *page_address(const struct page *page)
{
	unsigned long flags;
	void *ret;
	struct page_address_slot *pas;

	/**
	 * 如果页框不在高端内存中(PG_highmem标志为0)，则线性地址总是存在的。
	 * 并且通过计算页框下标，然后将其转换成物理地址，最后根据物理地址得到线性地址。
	 * 如果不是高端内存，则直接返回其线性地址
	 */
	if (!PageHighMem(page))
		/**
		 * 本句等价于__va((unsigned long)(page - mem_map) << 12)
		 */
		return lowmem_page_address(page);

	/* 计算在page_address_htable中的位置 */
	/**
	 * 否则页框在高端内存中(PG_highmem标志为1)，则到page_address_htable散列表中查找。
	 */
	pas = page_slot(page);
	ret = NULL;
	/* 获取桶的锁 */
	spin_lock_irqsave(&pas->lock, flags);
	/* 桶不为空 */
	if (!list_empty(&pas->lh)) {
		struct page_address_map *pam;

		/* 在桶中遍历 */
		list_for_each_entry(pam, &pas->lh, list) {
			/**
			 * 在page_address_htable中找到，返回对应的物理地址。
			 * 找到该页，并返回其地址
			 */
			if (pam->page == page) {
				ret = pam->virtual;
				goto done;
			}
		}
	}
	/**
	 * 没有在page_address_htable中找到，返回默认值NULL。
	 */
done:
	/* 释放锁并返回结果 */
	spin_unlock_irqrestore(&pas->lock, flags);
	return ret;
}

EXPORT_SYMBOL(page_address);

/**
 * set_page_address - set a page's virtual address
 * @page: &struct page to set
 * @virtual: virtual address to use
 */
void set_page_address(struct page *page, void *virtual)
{
	unsigned long flags;
	struct page_address_slot *pas;
	struct page_address_map *pam;

	BUG_ON(!PageHighMem(page));

	pas = page_slot(page);
	if (virtual) {		/* Add */
		pam = &page_address_maps[PKMAP_NR((unsigned long)virtual)];
		pam->page = page;
		pam->virtual = virtual;

		spin_lock_irqsave(&pas->lock, flags);
		list_add_tail(&pam->list, &pas->lh);
		spin_unlock_irqrestore(&pas->lock, flags);
	} else {		/* Remove */
		spin_lock_irqsave(&pas->lock, flags);
		list_for_each_entry(pam, &pas->lh, list) {
			if (pam->page == page) {
				list_del(&pam->list);
				spin_unlock_irqrestore(&pas->lock, flags);
				goto done;
			}
		}
		spin_unlock_irqrestore(&pas->lock, flags);
	}
done:
	return;
}

void __init page_address_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(page_address_htable); i++) {
		INIT_LIST_HEAD(&page_address_htable[i].lh);
		spin_lock_init(&page_address_htable[i].lock);
	}
}

#endif	/* defined(CONFIG_HIGHMEM) && !defined(WANT_PAGE_VIRTUAL) */
